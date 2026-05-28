# wotw-verify threat model

This document enumerates what `wotw-verify` does and does not defend
against, and the trust assumptions it operates under.

---

## What `wotw-verify` proves

Given:

- A Compliance Pack `P` containing a chain of provenance records
- The workspace KEK `K` (32 bytes, delivered out-of-band)
- A `wotw-verify` binary whose cosign signature you trust

If `wotw-verify P --workspace-key=K` exits 0 with verdict `verified`,
the verifier asserts:

1. **Chain integrity.** Every record's `id` equals
   `sha256(canonicalJson(payload))`. Tampering with any
   canonical-payload field (timestamp, source files, prompt hash,
   wiki file hashes, etc.) produces a different `id`, which fails
   recompute.
2. **Chain linkage.** Every record's `previous_chain_hash` equals
   the prior record's `chain_hash`. Removing a middle record (or
   inserting a new one) breaks the chain.
3. **Chain attestation.** Every record's `hmac` field equals
   `HMAC-SHA256(dek, id + "|" + chain_hash)` under the DEK
   identified by `key_id`. The DEK was previously sealed under `K`
   in `keys.json`. Without `K`, an attacker cannot mint a record
   the verifier would accept, even with full read access to the
   pack.

Together these three guarantees mean a verified pack is **immutable
after generation**: any post-hoc tampering by anyone who lacks `K`
will fail verification.

---

## What `wotw-verify` does NOT prove

### 1. The pack contents are factually correct

The verifier proves the chain has not been tampered with. It does NOT
prove:

- That the wiki content the chain references was sourced from a
  legitimate place.
- That the prompts fed to the LLM accurately described the source.
- That the LLM's response was faithful to its prompt.
- That the source files (`source_files` with `source_hashes`) actually
  contained what the workspace owner claims.

Provenance is a witness to **process**, not a witness to **truth**.
For a stronger guarantee, pair `wotw-verify` with content audits
(human review of `source_files` against `wiki_files_written`).

### 2. The workspace owner did not collude with 3030 Labs

A workspace owner with cooperation from 3030 Labs could:

- Backdate `timestamp` fields when generating the pack (the timestamp
  is part of the canonical payload, but the workspace owner controls
  what they sign).
- Omit records that were inconvenient (the chain only attests to
  records IT contains; it cannot prove no other records ever existed).
- Generate a fresh chain that has no relationship to the workspace's
  actual operational history.

To defend against collusion, augment with:

- Periodic third-party-anchored chain heads (publish `chain_hash` at
  intervals to a public anchor like a Bitcoin transaction or a
  trusted timestamping service).
- Cross-workspace consistency: if multiple workspaces touch overlapping
  sources, their chains should be mutually consistent.

### 3. The cosign public key in this repo is genuinely 3030 Labs'

`cosign.pub` in this repo is published by 3030 Labs. The trust chain
for that key is:

```
You trust            because               which trusts
─────                ────────              ───────────
GitHub.com           SSL CA (Let's Encrypt) WebPKI roots in your OS
3030 Labs org        GitHub authentication of the org owner
cosign.pub commit    Git history (3030 Labs' release process)
```

If any link in that chain is compromised (rogue Git commit, GitHub
account takeover, malicious code in the release-bot CI), an adversary
could swap `cosign.pub`. Defenses:

- Pin the key in your install script / pipeline by SHA-256 once
  you've verified the first one out-of-band.
- The same `cosign.pub` is also published at
  `wotw.dev/keys/wotw-verify.pub`. Compare both sources.
- Use Sigstore's transparency log (`rekor`) to detect retroactive
  swaps of the signing identity (planned for v0.2; v0.1.0 uses
  key-based signing only).

### 4. The binary you downloaded was not tampered post-cosign

Cosign signs the artifact. The artifact's checksum is in a signed
checksums file. Both are verified by the install script before
extraction. But once the binary lands on disk, it's just a file —
anyone with root on your machine can replace it. Defenses:

- Run `wotw-verify --self-test` after install. If the binary has
  been replaced with malicious code, the embedded self-test should
  fail (assuming the attacker didn't also patch the self-test).
- Pin the binary's expected SHA-256 in your `Brewfile` or install
  script.

### 5. The KEK was not exfiltrated

If `K` is exfiltrated, an attacker can mint records that pass HMAC
verification. The verifier cannot detect this — by design, anyone
with `K` is treated as authoritative. The KEK is the root of trust
on the customer side.

Defenses:

- Keep `K` in a hardware security module / cloud KMS.
- Rotate `K` periodically via the wotw daemon's `wotw workspace
  rotate-kek` operation (see [daemon docs](https://github.com/3030-Labs/watcher-on-the-wall/blob/main/docs/policies/kek-rotation.md)).
- A rotated `K` invalidates an attacker's stolen copy for any records
  written after rotation — but past records remain forge-able by
  whoever held the old `K` at the time.

---

## Trust assumptions, summarized

| Assumption                                            | If violated, what happens                                          |
|-------------------------------------------------------|--------------------------------------------------------------------|
| You hold the genuine KEK `K`                          | Attacker can mint records that verify.                             |
| `K` is delivered out-of-band (not in the pack)        | Pack distribution is sufficient; KEK distribution is separate.     |
| The `cosign.pub` you used is genuinely 3030 Labs'    | Attacker could distribute a malicious `wotw-verify` binary.         |
| The Go stdlib `crypto/sha256` + `crypto/hmac` are sound | Unknown — if SHA-256 is broken, the whole chain collapses.         |
| AES-256-GCM is sound                                  | Unknown — if AES-GCM is broken, DEKs can be recovered.             |
| The daemon was not malicious when the chain was written | Chain reflects whatever the daemon did; no defense from the verifier. |

---

## Side channels

`wotw-verify` runs offline. It:

- Does NOT make any network requests.
- Does NOT read any environment variable other than the standard Go
  runtime ones.
- Does NOT write anything outside its current working directory
  (except `--self-test` which writes to `os.MkdirTemp` and deletes
  on exit).
- Does NOT log to a remote endpoint.

Telemetry, crash reporting, and update checks are not present in this
binary. By design.

If you need stronger isolation guarantees, run `wotw-verify` in a
container or jailed VM with no network access.

---

## Reporting a vulnerability

Email `security@3030labs.io`. PGP key fingerprint published at
`wotw.dev/security`.

Do not file public issues for security vulnerabilities. We will
coordinate disclosure on a best-effort basis.
