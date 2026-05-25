# PASS-018 — G5 End-to-End Attestation Closure

**Status:** ✅ Closed
**Date:** 2026-05-24
**Daemon version:** v0.8.2
**Implementation commit:** `574d34f` — `feat(provenance-g5): end-to-end attestation substrate`
**Scaffolding precedent:** `1875925` (Layer-1 review items 37/38/42/43/44, May-23)
**Closes:** CT1.01 🟡 PARTIAL → ✅

This pass closes the workspace-key substrate the G5 scaffolding left as a
stub. Every CT-tier feature downstream of CT1.01 (CT1.02-CT5.03 in the v3
checklist) is unblocked by this ship.

---

## 1. What scaffolding shipped vs. what closure adds

The Layer-1 G5 scaffolding (commit `1875925`) shipped:
- `tenant_id` folded into canonical payload (item 43)
- `verify_on_startup` flipped to true (item 37)
- `init()` recomputes tail id + chain_hash (item 38)
- HMAC field on records signed under a 4-tier resolved key (item 42)
- Single static key for the lifetime of a daemon process

What was **missing** for end-to-end attestation:
- Per-workspace key lifecycle (provision, rotate, archive, revoke)
- Encryption at rest for signing keys (keys lived in env or were derived in-process)
- Rotation with overlap window (records signed by old key still verifiable)
- Actual HMAC verification in `verify()` — the scaffolding signed but never checked
- An audit surface (`/internal/verify`)

This pass ships all five.

## 2. Architecture

### Storage

`.wotw/keys.db` — new SQLite file, parallel to `.wotw/facts.db` from Pass B.
Schema v1 (idempotent migration via `PRAGMA user_version`):

```sql
CREATE TABLE workspace_keys (
  key_id TEXT PRIMARY KEY,                    -- UUIDv4
  workspace_id TEXT NOT NULL,                 -- = tenant_id today
  key_state TEXT NOT NULL CHECK (key_state IN ('active','rotating','archived','revoked')),
  encrypted_dek BLOB NOT NULL,                -- AES-256-GCM ciphertext under KEK
  nonce BLOB NOT NULL,                        -- 12-byte AES-GCM IV
  auth_tag BLOB NOT NULL,                     -- 16-byte AES-GCM auth tag
  created_at TEXT NOT NULL,
  rotated_at TEXT,
  revoked_at TEXT
);
CREATE INDEX idx_workspace_keys_workspace ON workspace_keys(workspace_id);
CREATE INDEX idx_workspace_keys_state ON workspace_keys(workspace_id, key_state);
CREATE UNIQUE INDEX idx_workspace_keys_one_active
  ON workspace_keys(workspace_id) WHERE key_state = 'active';
```

The partial unique index enforces **at most one active key per workspace** at
the database level — defense against a logic bug in `rotate()` that could
otherwise leave two `active` rows.

### Envelope encryption (KEK / DEK)

- **KEK** (key-encryption-key): 32 bytes, base64- or hex-encoded in
  `WOTW_WORKSPACE_KEK` Fly secret. Read once at daemon boot via
  `readKekFromEnv()`. Never written to disk. Validation: fails loud on
  wrong length or unparseable encoding.
- **DEK** (data-encryption-key): 32 random bytes per key from
  `crypto.randomBytes(32)`. Encrypted under the KEK with AES-256-GCM and
  a fresh 12-byte nonce. Stored as three BLOB columns (`encrypted_dek`,
  `nonce`, `auth_tag`).
- **Tamper detection**: GCM auth tag mismatches throw on `unwrapDek()`.
  Tampering with ciphertext, nonce, or auth tag all surface as crypto
  errors. Wrong KEK also throws.
- **In-process caching**: plaintext DEKs cached in a `Map<key_id, Buffer>`
  after first decrypt. Bounded by the number of keys per workspace
  (typically 1-3 during overlap windows).

### Rotation FSM

States: `active` → `rotating` → `archived`; `revoked` is terminal-immediate.

```
                provision()
                    │
                    ▼
                 active
                    │
                rotate()       ┌───── new active
                    │          │
                    ▼          ▼
                rotating    archived
                    │       (after overlap)
              archive() / overlap expires
                    │
                    ▼
                 archived
                                  ▼
                  revoke()  ───►  revoked  (forensic; cryptographic verify
                                            still passes, operator decides
                                            whether to trust)
```

- `rotate()` runs in a single SQLite transaction: updates old active to
  `rotating`, inserts new active. Concurrent rotations are guarded both
  by transaction atomicity AND the partial unique index.
- `archive()` is idempotent: archiving an already-archived key is a no-op.
- `revoke()` is terminal-immediate from any state. The DEK plaintext
  can still be unwrapped via `resolveById()` (for cryptographic verify),
  but `key_state === "revoked"` flags the record to operators.

### Attestation flow (append)

1. `ProvenanceChain.append(input)` computes `id` + `chain_hash` as before.
2. If `keyStore + workspaceId` set: `keyStore.active(workspaceId)`
   returns the active DEK + `key_id`. HMAC-SHA256 over `${id}|${chain_hash}`
   under the DEK. Record stamped with `hmac` AND `key_id`.
3. Else if `hmacKey` (single-key fallback) set: HMAC under the fallback
   key. Record stamped with `hmac` only. **Backward-compat path** — what
   a v0.8.1 daemon does.
4. Else: no HMAC. Pre-G5 record shape.

`key_id` is **excluded from canonical payload** — same boundary as
`hmac`, `fact_hashes_added`, `fact_hashes_superseded`. Old daemons compute
identical `id` and `chain_hash` on records carrying it. See
`[[project-provenance-compat]]` for the pattern.

### Verification flow (verify + init tail-verify)

For each record:
1. **canonical payload recompute** (id + chain_hash): unchanged except
   for one latent-bug fix — `verify()` now includes `tenant_id` in the
   recomputed payload (it was being included by `append()` and
   `init()` tail-verify, but `verify()`'s walk was missing it, which
   would have surfaced a false-positive `id hash mismatch` on any
   chain with tenant_id once HMAC verify started actually running).
2. **HMAC validation**:
   - `record.key_id` set → `keyStore.resolveById(key_id)` across ALL
     states (active/rotating/archived/revoked). Recompute HMAC,
     compare with `timingSafeEqual`.
   - `record.key_id` absent but `record.hmac` set → fall back to the
     single-key resolution (`this.hmacKey`). This handles v0.8.1-shape
     records inside a v0.8.2 daemon.
   - `record.hmac` absent → skip (pre-G5 record).
3. Tail-verify in `init()` runs `verifyHmac()` on the tail too — the
   tail is the most-likely tampering target and a tampered tail now
   refuses-to-start the daemon.

## 3. Backward and forward compatibility

Verified by tests in `test/unit/provenance-g5-attestation.test.ts`:

| Scenario | Behavior | Test |
|---|---|---|
| Pre-G5 chain (no `hmac` field) verifies under v0.8.2+ | ✓ | "a chain with no hmac field verifies under a v0.8.2+ daemon" |
| G5-scaffolding chain (`hmac`, no `key_id`) verifies under v0.8.2+ via 4-tier fallback | ✓ | "records with hmac+no-key_id verify under fallback hmacKey on a new daemon" |
| Mixed chain (some pre-G5 records, some G5-closed) verifies end-to-end | ✓ | "a mixed chain... verifies end-to-end" |
| v0.8.2+ chain canonical `id` matches what an older daemon would compute | ✓ | "canonical id recomputed without key_id/hmac/fact_hashes matches the stored id" |
| Mid-chain DEK rotation: records signed under previous DEK still verify | ✓ | "records signed under previous DEK still verify after rotate" |
| Revoked key still verifies cryptographically | ✓ | "after old DEK is revoked, records signed under it still verify cryptographically" |
| Tampered hmac → init() refuses to start | ✓ | "verify uses timing-safe comparison on the hmac field" |
| Tampered key_id (pointing at nonexistent key) → init() refuses to start | ✓ | "verify() with a missing key_id... surfaces error" |

## 4. /internal/verify endpoint contract

```
POST /internal/verify
Headers:
  x-admin-key: <WOTW_INTERNAL_ADMIN_KEY value>
  content-type: application/json
Body: { "tenant_id": "<workspace tenant_id>" }

Response 200 (chain valid):
  {
    "ok": true,
    "total_records": 1234,
    "verified_records": 1234,
    "errors": [],
    "duration_ms": 42
  }

Response 200 (chain has errors — endpoint succeeded, chain is broken):
  {
    "ok": false,
    "total_records": 1234,
    "verified_records": 1233,
    "errors": [
      { "seq": 567, "id": "<sha256>", "reason": "hmac mismatch (key_id=abc12345… state=active)" }
    ],
    "duration_ms": 38
  }

Response 401: unauthorized (missing or wrong x-admin-key)
Response 403: tenant_id mismatch (body.tenant_id != daemon config.hosted.tenant_id)
Response 503: { "error": "provenance_disabled" }
```

This surface is frozen — the future `wotw-verify` Go CLI (CT5.01,
separate pass) will consume this contract verbatim.

## 5. Bench: HMAC overhead per append

Hard gate: **p99 added latency < 1ms**.

Measured (1000-iteration runs, `test/bench/g5-hmac-overhead.bench.ts`):

| Metric | Baseline (no HMAC) | Attested (KeyStore) | Overhead |
|---|---|---|---|
| p50 | 2.028ms | 1.937ms | -0.091ms (within noise) |
| p95 | 2.853ms | 2.815ms | -0.038ms |
| p99 | 3.871ms | 4.334ms | **+0.463ms** |

Result: **0.463ms p99 overhead, well under the 1ms budget**.

The dominant cost of `append()` is `fsync` on the JSONL file (low
milliseconds). HMAC-SHA256 over a ~150-byte input (the id + chain_hash
concatenation) is microseconds. The overhead measurement is mostly
captured noise from variable fsync timing across runs — the actual
compute cost of HMAC is below the resolution of `performance.now()`.

## 6. Test count

| Test type | Pre-Pass-018 | Pass-018 adds | Post |
|---|---|---|---|
| Total tests | 752 | +61 | **813** |
| Files | 78 | +5 | 83 |
| New: envelope unit | — | 19 | — |
| New: store unit | — | 24 | — |
| New: G5 attestation unit | — | 12 | — |
| New: /internal/verify integration | — | 5 | — |
| New: HMAC overhead bench | — | 1 | — |

All 7 daemon gates green at HEAD `574d34f`:
- typecheck: ✓
- lint: ✓ (0 errors, 0 warnings)
- format:check: ✓
- test: ✓ 813 passed (813)
- build: ✓
- check-llm-types-sync: ✓ byte-identical with cloud
- check-chain-hash-sync: ✓ byte-identical with cloud

## 7. Operational notes

### Activation conditions

The full G5 attestation path requires **all of**:
1. `provenance.enabled: true` in config (default true)
2. `hosted.enabled: true` + `hosted.tenant_id` set (workspace_id source)
3. `WOTW_WORKSPACE_KEK` set in env (32 bytes, base64 or hex)

If any are missing, the daemon falls back to the v0.8.1 single-key
resolution (env / derive-from-tenant-id / undefined). This is by
design — single-user / interactive mode doesn't need workspace-level
keys, and the v0.8.1 fallback shape verifies identically.

### Boot behavior

On daemon boot with G5 active:
1. Open `.wotw/keys.db` (creates schema v1 if absent).
2. `keyStore.active(workspaceId)`:
   - returns existing → log `keyId=<8 chars>` at info
   - returns null → provision new active DEK, log `new DEK provisioned`
3. Pass `keyStore + workspaceId` to `ProvenanceChain` constructor.
4. `chain.init()` runs tail-verify including HMAC; refuses to start on
   tamper.

### KEK custody

`WOTW_WORKSPACE_KEK` is a Fly secret managed by the cloud orchestrator.
It MUST NOT be checked into git or printed in logs. The daemon's logger
redaction list (`src/utils/logger.ts`) catches `WOTW_*` prefix env
references; spot-verified that `WOTW_WORKSPACE_KEK` is in the redacted
set by inheritance from the existing `env.WOTW_*` patterns.

KEK rotation is **deferred** to a future pass (separate `/goal`). The
rotation procedure: re-encrypt every DEK in `workspace_keys` under the
new KEK in a single transaction, then update the Fly secret. Daemon
boots with the new KEK without losing access to any historical key.

### DEK rotation

Operator-driven via `wotw keys rotate` CLI. Atomic SQLite transaction:
new active DEK provisioned + old active transitions to `rotating`. New
appends sign under new DEK; verify recognizes records signed by either
DEK during the overlap window.

After the overlap window (operator-determined; default in `/goal` was
24h but no automatic scheduler ships this pass — defer to a cron in a
follow-up if needed), call `KeyStore.archive(previous_key_id)` to mark
the old DEK verify-only. The CLI `wotw keys list --json` surface
exposes the state machine for operator inspection.

### Compromise response

If a DEK is suspected compromised:
1. `KeyStore.revoke(key_id)` — flips state to `revoked` immediately.
2. Records signed under the revoked DEK still verify cryptographically
   (the math doesn't care about state); operators see `key_state="revoked"`
   in the verify response and decide whether to trust those records.
3. Next `wotw keys rotate` brings up a fresh active DEK.

## 8. Canon entry: workspace-key-substrate pattern

The substrate shipped here is **the standing pattern for any future
per-workspace cryptographic key**, not a one-off for HMAC signing. When
Pack signing lands (Pack Marketplace M4, Section 8 of v3 checklist), it
should use the same pattern:

1. New SQLite file at `.wotw/<purpose>.db` with a state-machine table.
2. KEK in Fly secrets, distinct from `WOTW_WORKSPACE_KEK` (one KEK per
   purpose, not a shared one — limits blast radius).
3. DEK lifecycle: `provision → active → rotating → archived` + terminal
   `revoked`. Partial unique index enforcing one-active-per-workspace at
   the DB level.
4. AES-256-GCM envelope with separate `ciphertext` / `nonce` / `auth_tag`
   columns. DEK plaintext only in process memory.
5. `key_id` on signed records, excluded from canonical payload (records
   are forward-compat with older daemons).
6. Audit endpoint `/internal/<verb>` admin-keyed; surface frozen for
   external CLIs.

## 9. What's next (out of scope of this pass)

- **CT1.02** — Compliance tier checkout SKU + Stripe Price ID
- **CT2.01-2.02** — Retention policies UI + enforcement cron
- **CT3.01-3.02** — Redaction audit + RLS immutability
- **CT4.01-4.02** — Compliance Pack export
- **CT5.01-5.03** — `wotw-verify` Go binary + distribution + docs
  (consumes the `/internal/verify` contract frozen here)
- **KEK rotation procedure** — re-encrypt every DEK under new KEK,
  Fly secret swap, no chain downtime
- **Auto-archive cron** — automatic `archive(rotating_key_id)` after a
  configurable overlap window (default 24h per the goal directive,
  but no scheduler shipped this pass)

## 10. Handoff

The v0.8.2 daemon image is **not built and pushed** in this pass — the
goal directive scoped to the source closure. A separate `SHIP-V0.8.2.md`
pass (following the v0.8.1 ship pattern) will build, push, and capture
the manifest digest for cloud's `FLY_DAEMON_IMAGE` rev bump. That pass
will also exercise the build-time `RUN node -e '<better-sqlite3 SQL>'`
gate added in v0.8.1 — keys.db creation and KEK env-var handling do
not run at image-build time (no KEK present in the build env), only at
daemon boot.

---

**Authority:** Implementation commit `574d34f`. Gate evidence captured
in this pass; benchmark numbers from `test/bench/g5-hmac-overhead.bench.ts`
in the `pnpm test` run at the same HEAD.
