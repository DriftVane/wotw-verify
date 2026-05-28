# wotw verification protocol (v1)

This document specifies the verification algorithm `wotw-verify`
implements. The intent is that any independent implementor — in Rust,
Python, JVM languages, etc. — can build a verifier that produces
bit-identical results on the same inputs, by following this document
alone.

The reference contract this verifier consumes is frozen in
[PASS-018-G5-CLOSURE.md §4](https://github.com/3030-Labs/watcher-on-the-wall/blob/main/PASS-018-G5-CLOSURE.md)
of the watcher-on-the-wall (daemon) repo. An embedded copy is shipped
at [`internal/contract/pass-018-g5-closure.md`](../internal/contract/pass-018-g5-closure.md)
and its content hash is asserted at compile time
(`PASS018Hash` in [`internal/contract/contract.go`](../internal/contract/contract.go)).

---

## 1. Compliance Pack format (v1)

A pack is either a directory tree or a `.zip` archive containing:

```
<pack>/
  manifest.json       — required
  chain.jsonl         — required
  keys.json           — required if chain has G5 attestation
  content/            — optional
```

### 1.1 manifest.json

```json
{
  "version": 1,
  "tenant_id": "<uuid>",
  "summary": "...",
  "created_at": "2026-05-25T12:00:00Z"
}
```

`version` MUST be exactly `1`. `tenant_id` is the workspace identifier
the chain records belong to. `summary` and `created_at` are optional.

### 1.2 chain.jsonl

One JSON object per line, newline-separated. Each object is a
ProvenanceRecord (see §2). Blank lines are skipped. Comments are not
permitted.

### 1.3 keys.json

```json
{
  "version": 1,
  "workspace_id": "<tenant_id>",
  "keys": [
    {
      "key_id": "<uuid>",
      "key_state": "active" | "rotating" | "archived" | "revoked",
      "created_at": "<iso8601>",
      "rotated_at": null | "<iso8601>",
      "revoked_at": null | "<iso8601>",
      "encrypted_dek_hex": "<aes-256-gcm-ciphertext>",
      "nonce_hex":         "<12-byte-iv>",
      "auth_tag_hex":      "<16-byte-gcm-tag>"
    }
  ]
}
```

Each DEK (data-encryption-key) is 32 bytes of plaintext, encrypted
under the workspace KEK (key-encryption-key) using AES-256-GCM.

---

## 2. ProvenanceRecord shape

```typescript
interface ProvenanceRecord {
  // === IDENTITY ===
  id: string;                       // sha256(canonicalJson(payload))
  chain_hash: string;               // sha256(previous_chain_hash + id)

  // === CANONICAL PAYLOAD (INCLUDED IN id) ===
  seq: number;                      // 1, 2, 3, ... strict increment
  timestamp: string;                // ISO-8601 UTC
  type: string;                     // ingest | query | compound | ...
  source_files: string[];
  source_hashes: string[];
  prompt_hash: string;
  model_id: string;
  response_hash: string;
  wiki_files_written: string[];
  wiki_file_hashes_after: Record<string, string>;
  previous_id: string | null;       // prior record's id, or null at start
  previous_chain_hash: string;      // prior record's chain_hash, or 64*"0"
  tenant_id?: string;               // workspace identifier (when present)
  metadata?: Record<string, ...>;   // arbitrary metadata (when present)

  // === ATTESTATION (EXCLUDED FROM id) ===
  hmac?: string;                    // HMAC-SHA256(dek, id + "|" + chain_hash)
  key_id?: string;                  // identifies which DEK signed `hmac`

  // === BACKWARD-COMPAT NOTES (EXCLUDED FROM id) ===
  fact_hashes_added?: string[];
  fact_hashes_superseded?: string[];
  merkle_root?: string;
}
```

The CANONICAL PAYLOAD section is what `id` hashes. The ATTESTATION and
BACKWARD-COMPAT sections are stored on the record but NEVER included
in `id` recomputation. This is the
[canonical-payload-exclusion pattern](https://github.com/3030-Labs/watcher-on-the-wall/blob/main/PASS-018-G5-CLOSURE.md):
records produced by newer daemons (that carry new optional fields)
verify bit-identically under older daemons that don't know about
those fields.

---

## 3. Canonical JSON

`canonicalJson(value)` is JavaScript's `JSON.stringify(normalize(value))`
where `normalize` recursively sorts object keys lexicographically.
Concretely:

- Object keys are emitted in lexicographic byte order.
- Arrays preserve insertion order.
- Strings:
  - Wrapped in `"`.
  - Backslash-escape: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`.
  - `\u00XX` escape for control characters `U+0000..U+001F` not
    covered by named escapes.
  - HTML characters `<`, `>`, `&` are NOT escaped.
  - Non-ASCII multibyte UTF-8 (including `U+2028` LINE SEPARATOR and
    `U+2029` PARAGRAPH SEPARATOR) passes through verbatim.
- Numbers:
  - Integers serialize bare (`1`, not `1.0`).
  - Non-integer finite floats use the shortest-round-trip
    representation (`%g` with default precision).
  - `Infinity` / `NaN` are not valid JSON; encoder must error.
- `true`, `false`, `null` render in lowercase.
- No whitespace anywhere (no indentation, no trailing newline).

Reference: [`internal/canonical/canonical.go`](../internal/canonical/canonical.go).
The encoder is byte-validated against the daemon's `canonicalJson` in
`internal/canonical/canonical_test.go::TestByteIdentityWithDaemonRuntime`.

---

## 4. Chain verification algorithm

For each record `r` in `chain.jsonl`, in file order:

### 4.1 Strict-increment seq

```
expected_seq = (previous record's seq) + 1, OR 1 for the first record
assert r.seq == expected_seq
```

### 4.2 Linkage

```
assert r.previous_id == (previous record's id), OR null for the first record
assert r.previous_chain_hash == (previous record's chain_hash), OR
       "0" * 64 (GENESIS_HASH) for the first record
```

### 4.3 Canonical id recompute

```
payload = r minus { id, chain_hash, hmac, key_id, fact_hashes_*, merkle_root }
expected_id = sha256(canonicalJson(payload))
assert expected_id == r.id
```

CRUCIAL: a record's `payload` recompute uses the SAME conditional-
inclusion the daemon used at write time. If `metadata` is absent from
the source JSON, the recomputed payload must also exclude
`metadata` — not include it as `null` or `{}`. Same for `tenant_id`.

### 4.4 Chain hash recompute

```
expected_chain_hash = sha256(r.previous_chain_hash + r.id)
                                              ^
                          plain ASCII concatenation of the two hex strings
assert expected_chain_hash == r.chain_hash
```

### 4.5 HMAC verification (when `r.hmac` is present)

```
if r.key_id is present:
    dek = decrypt_dek(keys.json[key_id], KEK)
    assert dek is not None  # else: hmac key_id=<x> not found
else:
    dek = fallback_key  # tier 4 resolution; usually unavailable in verify
    assert dek is not None  # else: pre-G5 HMAC + no fallback key

expected = HMAC-SHA256(dek, r.id + "|" + r.chain_hash)
                                  ^
                       ASCII string concatenation with pipe separator
assert constant_time_eq(hex_decode(r.hmac), expected)
```

Use a constant-time comparison to defeat timing attacks on the HMAC
field. Go's `crypto/subtle.ConstantTimeCompare` (or Node's
`crypto.timingSafeEqual`) is the right primitive.

### 4.6 DEK envelope decryption

```
ciphertext = hex_decode(key_record.encrypted_dek_hex)
nonce      = hex_decode(key_record.nonce_hex)
auth_tag   = hex_decode(key_record.auth_tag_hex)

dek = AES-256-GCM.decrypt(
    key = KEK,
    iv = nonce,
    ciphertext = ciphertext || auth_tag,  # Go's gcm.Open wants them concatenated
    aad = nil
)
assert len(dek) == 32
```

A wrong KEK or tampered ciphertext/nonce/auth_tag surfaces as a GCM
authentication failure. The verifier MUST surface this as a clear
"wrong KEK or tampered DEK" error, not silently fall through.

---

## 5. Rotation semantics

A workspace DEK lifecycle is `active → rotating → archived`, with
`revoked` as a terminal state from any other.

Records signed under a previous active DEK still verify after
rotation: the verifier resolves the DEK by `key_id`, regardless of
the key's current state. A record signed by an `archived` or even a
`revoked` DEK is cryptographically valid — but the verifier surfaces
the key state in the per-record status so an operator can decide
whether to trust those records (e.g., if the DEK was revoked due to
suspected compromise, records signed under it MAY be untrustworthy
even though they verify).

`wotw-verify --json` reports `key_state` per record. Auditors are
expected to flag records signed under non-`active` keys for human
review.

---

## 6. Strict mode

`--strict` refuses to verify any chain containing records WITHOUT an
`hmac` field (i.e., pre-G5 records produced by daemon v0.8.1 and
earlier). Non-strict mode reports these as `unattested` in the per-
record status and accepts the chain overall (assuming all other
checks pass).

Pre-G5 chains are cryptographically attestable only by the daemon
that wrote them (the daemon's 4-tier fallback HMAC key was derived
from environment + tenant ID). A customer with only the chain + a
KEK CANNOT verify HMAC on pre-G5 records — the fallback key
construction is daemon-side state. Strict mode exists for customers
who require every record in the chain to have a verifier-checkable
attestation.

---

## 7. Edge cases

| Scenario                                           | Behavior                                                         |
|----------------------------------------------------|------------------------------------------------------------------|
| `chain.jsonl` empty                                | verdict `verified`, total_records 0                              |
| `manifest.json` missing                            | verdict `malformed`, exit 2                                      |
| `manifest.json` version != 1                       | verdict `malformed`, exit 2                                      |
| `keys.json` present but `KEK` not supplied         | resolver fails per-record; chain marked failed if any HMAC       |
| `KEK` supplied but `keys.json` absent              | verifier ignores KEK; chain verified by linkage only             |
| `keys.json` references a `key_id` not in chain     | ignored — extra keys are not an error                            |
| chain references a `key_id` not in `keys.json`     | per-record HMAC error                                            |
| `revoked` DEK signs a record                       | record verifies (math doesn't care), key_state surfaced in status |
| `archived` DEK signs a record                      | record verifies                                                  |
| Single-record chain                                | linkage uses GENESIS_HASH; otherwise unchanged                   |
| Chain with seq gaps (e.g., 1,2,4)                  | seq mismatch error on record 4                                   |
| Tampered timestamp                                 | id hash recompute mismatches → chain failed                      |
| Tampered metadata                                  | id hash recompute mismatches → chain failed                      |
| Pack delivered as zip with a top-level directory   | accepted — verifier looks for manifest under any single-dir prefix |

---

## 8. Stability

This protocol is versioned at **v1**. The pack `manifest.json`
version + the embedded contract hash gate compatibility. Future
breaking changes will:

1. Bump `manifest.json.version` to 2.
2. Update `PASS018Hash` constant in [`internal/contract/contract.go`](../internal/contract/contract.go)
   in the same release.
3. Ship a new major release of `wotw-verify` that handles BOTH v1
   and v2 packs.

Older verifiers MUST refuse a v2 pack rather than silently misparsing
it.

---

## 9. Reference implementation conformance

A conforming reimplementation should pass the same 5 self-test
scenarios as `wotw-verify --self-test`:

1. **valid_g5** — 3 records, all HMAC + key_id, all in `active` state → `verified`
2. **tampered_content** — flip `wiki_file_hashes_after` on record 2 → `failed`
3. **tampered_hmac** — flip first hex char of record 2's `hmac` → `failed`
4. **mid_chain_rotation** — 2 records under key A (`rotating`), 2 under key B (`active`) → `verified`
5. **pre_g5_backward_compat** — 3 records, no `hmac` field → `verified_with_unattested_records` (non-strict) / `failed` (strict)

Match the verdict for each scenario.
