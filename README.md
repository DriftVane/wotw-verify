# wotw-verify

[![Go Reference](https://pkg.go.dev/badge/github.com/DriftVane/wotw-verify.svg)](https://pkg.go.dev/github.com/DriftVane/wotw-verify)
[![Release](https://img.shields.io/github/v/release/DriftVane/wotw-verify)](https://github.com/DriftVane/wotw-verify/releases)

`wotw-verify` is the **customer-verifiable trust primitive** for the
[watcher-on-the-wall (wotw) Compliance Pack](https://wotw.dev/compliance)
format.

A single statically-linked binary, < 5 MB on all platforms, with no
runtime dependencies. Given a Compliance Pack and the workspace
encryption key, it:

1. Re-computes every provenance record's canonical SHA-256 id.
2. Walks the hash-chain end-to-end, asserting `previous_chain_hash`
   linkage matches the prior record's `chain_hash`.
3. Decrypts each workspace DEK under the supplied KEK and verifies
   the HMAC-SHA256 attestation on every record.
4. Reports a structured verdict (`verified` / `failed` / `malformed`)
   suitable for compliance auditors, contract dispute resolution, or
   automated CI integration.

There is no network access, no telemetry, no daemon required.

---

## Install

### Homebrew (macOS, Linux)

```sh
brew install DriftVane/tap/wotw-verify
```

### One-line installer (Linux, macOS)

```sh
curl -fsSL https://install.wotw.dev/verify | sh
```

The installer downloads the binary for your platform, verifies its
cosign signature against [`cosign.pub`](./cosign.pub) in this repo,
then installs to `/usr/local/bin/wotw-verify`.

### Direct download

Each release on the [Releases page](https://github.com/DriftVane/wotw-verify/releases)
includes prebuilt binaries for:

| OS      | Architecture |
|---------|--------------|
| Linux   | x86_64       |
| Linux   | arm64        |
| macOS   | x86_64       |
| macOS   | arm64 (Apple Silicon) |
| Windows | x86_64       |

Every artifact is signed with cosign. Verify before extracting:

```sh
cosign verify-blob --key cosign.pub \
  --signature wotw-verify_0.1.0_linux_x86_64.tar.gz.sig \
  wotw-verify_0.1.0_linux_x86_64.tar.gz
```

### Build from source

```sh
go install github.com/DriftVane/wotw-verify/cmd/wotw-verify@latest
```

Requires Go 1.22+.

---

## Usage

### Verify a Compliance Pack

```sh
wotw-verify <pack-path> --workspace-key=path/to/kek.bin
```

A Compliance Pack is either a directory or a `.zip` file containing:

```
<pack>/
  manifest.json       (required)
  chain.jsonl         (required)
  keys.json           (required if chain has G5 attestation)
  content/            (optional — wiki files)
```

`--workspace-key` is a base64- or hex-encoded 32-byte KEK delivered
out-of-band by the workspace owner.

### Flags

| Flag                         | Purpose                                                    |
|------------------------------|------------------------------------------------------------|
| `--workspace-key=<path>`     | Path to the workspace KEK (32 bytes, base64 or hex).       |
| `--json`                     | Emit a machine-readable JSON report on stdout.             |
| `--strict`                   | Refuse any chain containing pre-G5 (un-HMAC'd) records.    |
| `--verbose`                  | Emit per-record outcomes in human mode.                    |
| `--self-test`                | Run the 5 embedded fixture scenarios and report.           |
| `--version`                  | Print binary version and exit.                             |
| `--help`                     | Show usage and exit.                                       |

### Exit codes

| Exit | Meaning                                                                                            |
|------|----------------------------------------------------------------------------------------------------|
| 0    | Chain verified. (Or verified-with-unattested-records in non-strict mode.)                          |
| 1    | Chain has at least one verification failure (id hash, chain linkage, or HMAC).                     |
| 2    | Malformed input — cannot parse pack, chain.jsonl, or keys.json. KEK file unreadable or wrong size. |

### `--json` output schema

```json
{
  "version": "1",
  "tool": "wotw-verify",
  "pack_path": "/path/to/pack",
  "verdict": "verified",
  "exit_code": 0,
  "chain_ok": true,
  "workspace_id": "<uuid>",
  "total_records": 1234,
  "verified_records": 1234,
  "attested_records": 1234,
  "unattested_total": 0,
  "failed_records": 0,
  "errors": [],
  "statuses": [...per-record...],
  "hmac_keys_resolved": 2,
  "strict_mode": false,
  "duration_ms": 18,
  "started_at": "2026-05-25T12:00:00Z"
}
```

See [`docs/verification-protocol.md`](./docs/verification-protocol.md)
for the complete contract.

### Self-test

`wotw-verify --self-test` runs 5 embedded scenarios in a temp directory
without needing a real Compliance Pack. Useful to confirm the binary
behaves correctly on a clean machine:

```
wotw-verify v0.1.0 self-test

  ✓  valid_g5                      got=verified/0  want=verified/0
  ✓  tampered_content              got=failed/1  want=failed/1
  ✓  tampered_hmac                 got=failed/1  want=failed/1
  ✓  mid_chain_rotation            got=verified/0  want=verified/0
  ✓  pre_g5_backward_compat        got=verified_with_unattested_records/0  want=verified_with_unattested_records/0
```

Exit code 0 if all 5 scenarios produce their expected verdict, 1 if
any fail.

---

## Documentation

| Document                                              | Purpose                                                     |
|-------------------------------------------------------|-------------------------------------------------------------|
| [`docs/verification-protocol.md`](./docs/verification-protocol.md) | The complete /internal/verify contract a reimplementor must follow. |
| [`docs/threat-model.md`](./docs/threat-model.md)      | What wotw-verify protects against; what it doesn't.         |
| [`docs/release-process.md`](./docs/release-process.md) | How DriftVane cuts a release + rotates the cosign signing key. |

---

## Trust assumptions

`wotw-verify` is a verifier — it can prove a chain was not tampered
with after the fact, **given the workspace key**. It does NOT prove:

- That the workspace owner did not collude with DriftVane to forge the
  pack at generation time.
- That the cosign public key in this repo is genuinely DriftVane's
  (you trust the published key chain).
- That the underlying source content the chain references
  (wiki/raw files) actually said what the pack claims.

The full threat model is in [`docs/threat-model.md`](./docs/threat-model.md).

---

## License

[Apache License 2.0](./LICENSE). Copyright 2026 DriftVane LLC.
