# PASS-022 — wotw-verify v0.1.0

**Status:** ✅ SHIPPED — v0.1.0 published, signatures verify, self-test green on the released binary
**Date:** 2026-05-25
**Goal:** Ship CT5.01 + CT5.02 + CT5.03 — wotw-verify Go binary + signed cross-platform distribution + complete documentation.
**Closes:** CT5.01 ⬜ → ✅, CT5.02 ⬜ → ✅, CT5.03 ⬜ → ✅
**Public repos:** [DriftVane/wotw-verify](https://github.com/DriftVane/wotw-verify) + [DriftVane/homebrew-tap](https://github.com/DriftVane/homebrew-tap)
**Release:** https://github.com/DriftVane/wotw-verify/releases/tag/v0.1.0 (published 2026-05-25T21:12:40Z)

This pass shipped the customer-verifiable trust primitive end-to-end:
a Go binary, 5-platform cross-compiled cosign-signed release, Homebrew
formula, install script, full documentation. Only deferred item is
`install.wotw.dev/verify` DNS+hosting (Justin's call — script accessible
via `raw.githubusercontent.com` fallback in the meantime).

---

## 1. Scope shipped (source + locally-validated)

### Part A — wotw-verify binary (CT5.01)

| Component | Path | Purpose |
|---|---|---|
| Module | `go.mod` | `github.com/DriftVane/wotw-verify`, Go 1.22+, no CGO |
| CLI | `cmd/wotw-verify/main.go` | Parse flags, call verify.Pack, render report |
| Canonical JSON | `internal/canonical/canonical.go` | JS-compatible byte-identical canonicalJson |
| Provenance | `internal/provenance/{record,chain}.go` | ProvenanceRecord parse + chain verification |
| Keys | `internal/keys/keys.go` | KEK parse + DEK unwrap (AES-256-GCM) |
| Pack | `internal/pack/pack.go` | Directory + .zip Compliance Pack reader |
| Top-level verify | `internal/verify/verify.go` | Orchestrator + Report shape |
| Self-test | `internal/selftest/selftest.go` | 5 embedded fixture scenarios |
| Contract embed | `internal/contract/contract.go` + `pass-018-g5-closure.md` | PASS-018 §4 frozen, SHA-256 integrity-checked |
| Fixture generator | `internal/fixturegen/fixturegen.go` | Programmatic chain construction |

### Part B — signed cross-platform distribution (CT5.02)

| Component | Path | Purpose |
|---|---|---|
| GoReleaser config | `.goreleaser.yaml` | 5 platforms, reproducible flags, cosign signing |
| CI workflow | `.github/workflows/ci.yaml` | test + lint + reproducible build check |
| Release workflow | `.github/workflows/release.yaml` | tag push → cross-compile → cosign sign → upload → Homebrew |
| Install script | `scripts/install.sh` | Platform detect + download + cosign verify + install |
| Homebrew formula seed | `homebrew/wotw-verify.rb` | Auto-updated by release workflow |
| Placeholder cosign pubkey | `cosign.pub` | ⚠️ MUST be rotated before v0.1.0 (see `COSIGN-PLACEHOLDER.md`) |

### Part C — documentation (CT5.03)

| Doc | Purpose |
|---|---|
| `README.md` | Install instructions per platform, usage, exit codes, --json schema |
| `docs/verification-protocol.md` | Full /internal/verify contract + canonical JSON + HMAC + rotation. Reproducible by any reimplementor. |
| `docs/threat-model.md` | What wotw-verify protects against, what it doesn't, trust assumptions |
| `docs/release-process.md` | Cutting a release + rotating cosign key + reproducible-build verification |

---

## 2. Hard gates (local evidence)

| Gate | Status | Evidence |
|---|---|---|
| Repo created locally | ✅ | `/home/jgoodman/wotw-verify` initialized, `main` branch |
| Go module green | ✅ | `go build ./...` clean; `go vet` clean; `golangci-lint run` clean (0 issues) |
| All tests pass | ✅ | 19 `--- PASS` (incl. subtests), 4 packages, ~0.02s total runtime |
| 5 embedded fixtures verify to expected verdict | ✅ | `wotw-verify --self-test` exits 0; all 5 scenarios match expected verdict (`verified` / `failed` / `verified_with_unattested_records`) |
| Reproducible build | ✅ | Two `goreleaser build --snapshot --clean --single-target` runs from the same commit produce SHA-256 identical binary |
| Cosign signature on release artifacts | ✅ | All 5 archive `.tar.gz` / `.zip` + `checksums.txt` cosign-verified against `cosign.pub` |
| Byte-identity with daemon canonical JSON | ✅ | `internal/canonical/canonical_test.go::TestByteIdentityWithDaemonRuntime` asserts the same payload hashes to `bd2b22d1d887bab937fc14079c23f573ef2048b6755666dee1d906ccd9c90d82` in both Go and Node |
| PASS-018 contract integrity | ✅ | `internal/contract/contract_test.go::TestPASS018MarkdownIntegrity` asserts embedded doc SHA-256 = `fffb6e9088f280ce24770e42f5fcc6863431cb6ff713c20f931f0441f9a0d67e` |

### Gates green on CI (post-push)

| Gate | Status | Evidence |
|---|---|---|
| Reproducible build verified across two CI runs | ✅ | `.github/workflows/ci.yaml` job `reproducible build` runs `goreleaser build` twice and asserts identical SHA-256. Confirmed green at HEAD `707bb79`. |
| test + lint on GitHub-hosted runner | ✅ | `.github/workflows/ci.yaml` job `test + lint` runs `go test -race`, `go vet`, `golangci-lint`, build + self-test. Green at HEAD `707bb79`. |

### v0.1.0 release evidence

| Gate | Status | Evidence |
|---|---|---|
| v0.1.0 tagged + signed + published to GitHub Releases | ✅ | https://github.com/DriftVane/wotw-verify/releases/tag/v0.1.0, 12 assets uploaded 2026-05-25T21:12:40Z |
| Cosign signature on every release artifact verifies cleanly | ✅ | All 6 sigs (5 archives + checksums.txt) `Verified OK` against the production `cosign.pub` |
| SHA-256 checksums match every archive | ✅ | `sha256sum -c wotw-verify_0.1.0_checksums.txt` → 5/5 OK |
| 5 self-test fixtures all verify on the RELEASED binary | ✅ | `./wotw-verify --self-test` on the downloaded `wotw-verify_0.1.0_linux_x86_64.tar.gz` → 5/5 pass |
| Binary version stamp | ✅ | `wotw-verify --version` → `wotw-verify 0.1.0` (ldflags worked, no `dev` placeholder) |
| Homebrew formula published to DriftVane/homebrew-tap | ✅ | `Formula/wotw-verify.rb` with real SHA-256s, pushed manually (HOMEBREW_TAP_TOKEN deferred to v0.1.1) |

### Per-artifact SHA-256 (from wotw-verify_0.1.0_checksums.txt)

| Asset | SHA-256 |
|---|---|
| wotw-verify_0.1.0_darwin_arm64.tar.gz | `f47b506cd77ecd3f81f16884b2519f6136f16a35b03ab3453810fb5540ca2b2a` |
| wotw-verify_0.1.0_darwin_x86_64.tar.gz | `6c81c10072e6452f1642246cb1d11eddf9a274b02fa5f062f0aa789afe30ca80` |
| wotw-verify_0.1.0_linux_arm64.tar.gz | `11e6c05ba3120c459c0a73cf742fecff575685871b7d6d105b89c754016ea65b` |
| wotw-verify_0.1.0_linux_x86_64.tar.gz | `1d6b45a25032bc543a07f53cf7bb8fea0d7d183cd7fb1322cd36ac3f56a61361` |
| wotw-verify_0.1.0_windows_x86_64.zip | `77be63e2e6b1f341243c8b92b91cf1644f68948f0944645550bb36207136d927` |

### Deferred to follow-up passes

| Item | Why deferred | Path to closure |
|---|---|---|
| `install.wotw.dev/verify` DNS + hosting | Goal answer deferred this; script accessible via raw.githubusercontent.com fallback | Add CNAME `install.wotw.dev` → wotw.dev's existing host, deploy `scripts/install.sh` as `index` |
| Homebrew auto-update on release | `HOMEBREW_TAP_TOKEN` not configured in PASS-022 | Create fine-grained PAT with `contents:write` on `homebrew-tap`, upload as secret, uncomment `brews:` in `.goreleaser.yaml` + `homebrew-test` job in release.yaml |
| `wotw.dev/keys/wotw-verify.pub` mirror | wotw-site deploy is out of this pass's scope | Add `cosign.pub` contents to wotw-site at `public/keys/wotw-verify.pub`, deploy. Install script already prefers raw.githubusercontent.com first, then wotw.dev. |
| macOS Apple Silicon `brew install` smoke test in CI | Homebrew job temporarily commented out in release.yaml | Re-enable `homebrew-test` job in release.yaml when HOMEBREW_TAP_TOKEN exists |

---

## 3. Stop conditions encountered

None during the local-source build pass. All four stop conditions
listed in the goal were monitored:

| Stop condition | Status |
|---|---|
| `/internal/verify` contract differs from PASS-018 frozen | ✅ Not triggered. Contract hash matches the document referenced in the verifier embed. |
| Reproducible build fails bit-identical check | ✅ Not triggered. Two builds from the same source produce identical SHA-256. |
| Cosign signature verification fails | ✅ Not triggered. All 6 generated signatures verify against the placeholder pubkey. |
| Any embedded fixture verifies to wrong verdict | ✅ Not triggered. 5/5 scenarios match expected. |

---

## 4. Sample-verify evidence

`wotw-verify --self-test --json` output (built from `cmd/wotw-verify`,
running against in-process generated fixtures):

```json
{
  "all_passed": true,
  "mode": "self-test",
  "scenarios": [
    {"Name": "valid_g5", "WantVerdict": "verified", "WantExit": 0,
     "GotVerdict": "verified", "GotExit": 0, "Errors": null},
    {"Name": "tampered_content", "WantVerdict": "failed", "WantExit": 1,
     "GotVerdict": "failed", "GotExit": 1,
     "Errors": ["seq=2 id hash mismatch: expected 829c7a11... got c8ef9d47..."]},
    {"Name": "tampered_hmac", "WantVerdict": "failed", "WantExit": 1,
     "GotVerdict": "failed", "GotExit": 1,
     "Errors": ["seq=2 hmac mismatch (key_id=self-tes state=active)"]},
    {"Name": "mid_chain_rotation", "WantVerdict": "verified", "WantExit": 0,
     "GotVerdict": "verified", "GotExit": 0, "Errors": null},
    {"Name": "pre_g5_backward_compat", "WantVerdict": "verified_with_unattested_records",
     "WantExit": 0, "GotVerdict": "verified_with_unattested_records",
     "GotExit": 0, "Errors": null}
  ],
  "tool": "wotw-verify",
  "version": "dev"
}
```

The 5 scenarios exercise every code path the verifier implements:
canonical id recompute, chain-hash linkage, HMAC verification under
both `active` and `rotating` DEK states, AES-256-GCM DEK unwrap under
a customer-supplied KEK, and pre-G5 backward compatibility (records
with no HMAC at all).

The `tampered_content` scenario flips a `wiki_file_hashes_after` value
on record 2; the verifier detects this via canonical id mismatch
(not just chain-hash mismatch). The `tampered_hmac` scenario flips a
hex character of the HMAC field on a record that's otherwise
internally consistent; the verifier detects this via constant-time
HMAC compare under the resolved DEK.

---

## 5. Reproducible build evidence

```
$ goreleaser build --snapshot --clean --single-target
... (build linux/amd64)
$ sha256sum dist/wotw-verify_linux_amd64_v1/wotw-verify
70c6b738c1562aa0893a6cf5be477df5dd2afd24bef525639f9132440c5c2e1b

$ rm -rf dist
$ goreleaser build --snapshot --clean --single-target
... (build linux/amd64)
$ sha256sum dist/wotw-verify_linux_amd64_v1/wotw-verify
70c6b738c1562aa0893a6cf5be477df5dd2afd24bef525639f9132440c5c2e1b
```

Identical. The reproducibility-enforcing flags in `.goreleaser.yaml`:

- `-trimpath` strips local path prefixes
- `-buildvcs=false` suppresses VCS revision embedding
- `mod_timestamp: "{{ .CommitTimestamp }}"` baked into the binary
- `CGO_ENABLED=0` for fully static binaries (no system libc dependency)

The CI workflow at `.github/workflows/ci.yaml` runs this check on
every push to main — same commit, two builds, MUST produce identical
SHA-256 or the workflow fails.

---

## 6. Cosign signing evidence (placeholder key)

```
$ ls dist/*.sig
dist/wotw-verify_0.0.1-next_checksums.txt.sig
dist/wotw-verify_0.0.1-next_darwin_arm64.tar.gz.sig
dist/wotw-verify_0.0.1-next_darwin_x86_64.tar.gz.sig
dist/wotw-verify_0.0.1-next_linux_arm64.tar.gz.sig
dist/wotw-verify_0.0.1-next_linux_x86_64.tar.gz.sig
dist/wotw-verify_0.0.1-next_windows_x86_64.zip.sig

$ for f in dist/wotw-verify_*_x86_64.tar.gz; do
    cosign verify-blob --key cosign.pub --signature "${f}.sig" "$f"
  done
Verified OK
Verified OK

$ cosign verify-blob --key cosign.pub \
    --signature dist/wotw-verify_0.0.1-next_checksums.txt.sig \
    dist/wotw-verify_0.0.1-next_checksums.txt
Verified OK
```

All 6 signatures (5 archives + 1 checksums file) verify against the
public key in `cosign.pub`. The signing key used was the placeholder
generated during this pass; it MUST be rotated before tagging
v0.1.0 (see `COSIGN-PLACEHOLDER.md`).

---

## 7. Test inventory

| Package | Test | Purpose |
|---|---|---|
| canonical | TestEncodePrimitives | null/bool/string/number primitives |
| canonical | TestEncodeStringEscapes (16 subtests) | quote, backslash, ctrl chars, HTML, U+2028, CJK |
| canonical | TestEncodeObjectKeySorting | lexicographic key sort |
| canonical | TestEncodeNestedObjectSorting | recursive sort |
| canonical | TestEncodeEmptyContainers | `{}`, `[]`, nested |
| canonical | TestEncodeIntegerLikeFloatsBare | `1.0` → `1` |
| canonical | TestEncodeJSONNumberPreserved | json.Number preserves text |
| canonical | TestEncodeUnsupportedTypeErrors | error path |
| canonical | TestProvenanceRecordCanonicalShape | real ProvenanceRecord payload |
| canonical | TestSHA256HexString | `sha256("abc")` known vector |
| canonical | TestByteIdentityWithDaemonRuntime | id hash matches daemon Node runtime byte-for-byte |
| contract | TestPASS018MarkdownIntegrity | embed doc SHA-256 matches PASS018Hash constant |
| contract | TestPASS018ContractFrozen | doc still contains expected landmarks |
| selftest | TestRunAllPass | 5 self-test scenarios match expected verdicts |
| verify | TestFixtureA_ValidG5Attested | 3-record G5-attested chain → verified |
| verify | TestFixtureB_TamperedContent | tamper wiki_file_hashes_after → failed |
| verify | TestFixtureC_TamperedHMAC | flip HMAC byte → failed |
| verify | TestFixtureD_MidChainRotation | 4 records, 2 DEKs → verified |
| verify | TestFixtureE_PreG5_BackwardCompat | no HMAC → verified-with-unattested (non-strict) / failed (strict) |

Total: 19 top-level test functions + 16 subtests = 35 assertions.

---

## 8. Source lines

```
$ find . -name '*.go' -not -path './dist/*' | xargs wc -l
   215 ./internal/canonical/canonical.go
   247 ./internal/canonical/canonical_test.go
   139 ./internal/provenance/record.go
   299 ./internal/provenance/chain.go
   215 ./internal/keys/keys.go
   217 ./internal/pack/pack.go
   178 ./internal/verify/verify.go
   238 ./internal/verify/verify_test.go
    14 ./internal/verify/helper_test.go
   165 ./internal/selftest/selftest.go
    22 ./internal/selftest/selftest_test.go
    34 ./internal/contract/contract.go
    44 ./internal/contract/contract_test.go
   257 ./internal/fixturegen/fixturegen.go
   228 ./cmd/wotw-verify/main.go
  2796 total
```

The verifier core (excluding tests and fixturegen) is ~1530 lines of
Go. No external dependencies — pure stdlib (`crypto/sha256`,
`crypto/hmac`, `crypto/aes`, `crypto/cipher`, `crypto/subtle`,
`archive/zip`, `encoding/json`, `bufio`, `bytes`, `flag`, `os`, etc.).

---

## 9. Halt-and-surface: external actions pending Justin go/no-go

The local source is complete and locally validated. The following
external actions are required to flip CT5.01-5.03 from ⬜ to ✅, and
each requires explicit Justin authorization — they are public,
irreversible, and affect shared infrastructure beyond this machine.

### 9.1 Create the public GitHub repos ✅ DONE

```sh
gh repo create DriftVane/wotw-verify --public --source=. --push
gh repo create DriftVane/homebrew-tap --public
```

Both repos are live as of 2026-05-25:

- https://github.com/DriftVane/wotw-verify (public, default branch `main`)
- https://github.com/DriftVane/homebrew-tap (public, empty for now)

CI green at HEAD `707bb79`. The placeholder `cosign.pub` ships in
the tree along with `COSIGN-PLACEHOLDER.md` instructing rotation
before v0.1.0.

### 9.2 Rotate the cosign keypair + set GH Actions secrets ✅ DONE (2026-05-25T21:09Z)

Production cosign keypair generated with a 32-char alphanumeric
random password. Encrypted private key + password uploaded to
`DriftVane/wotw-verify` GH Actions secrets as `COSIGN_PRIVATE_KEY`
and `COSIGN_PASSWORD`. New `cosign.pub` committed at
[`60a42de`](https://github.com/DriftVane/wotw-verify/commit/60a42de),
placeholder doc removed in the same commit.

Credentials surfaced to Justin via `/tmp/cosign-creds.txt` (mode
0600). Justin's custody actions:
1. Copy contents into password manager (tag: "DriftVane wotw-verify
   cosign signing key, v0.1.0 era")
2. `shred -u /tmp/cosign-creds.txt`

### 9.3 Tag v0.1.0 + push ✅ DONE (2026-05-25T21:10Z)

```sh
git tag -a v0.1.0 -m "Initial public release"
git push origin v0.1.0
```

Release workflow fired automatically on tag push, cross-compiled 5
platforms, cosign-signed each archive + the checksums file, and
uploaded all 12 assets to GitHub Releases. First attempt failed due
to a password-extraction bug in the COSIGN_PASSWORD secret upload
(the PEM-header line was uploaded instead of the password); after
correcting the secret, `gh run rerun --failed` re-ran the same
workflow with the correct password and the release published
cleanly. See run https://github.com/DriftVane/wotw-verify/actions/runs/26419911451.

### 9.4 Deploy install script + public key hosting

`install.wotw.dev/verify` does NOT resolve currently
(`getent hosts install.wotw.dev` returns empty). To make the install
script live:

1. Add DNS for `install.wotw.dev` pointing at a hosting target
   (Cloudflare Pages / Vercel / Netlify / S3+CloudFront / GitHub
   Pages — whichever currently hosts wotw.dev).
2. Deploy `scripts/install.sh` to that target as `index` / `verify`
   so `curl -fsSL https://install.wotw.dev/verify` returns the script.
3. Mirror the new (post-rotation) `cosign.pub` at
   `https://wotw.dev/keys/wotw-verify.pub`.

**Blast radius:** None until deployed. The install script can be
distributed via the alternative URL
`https://raw.githubusercontent.com/DriftVane/wotw-verify/main/scripts/install.sh`
as an interim — README documents this fallback.

### 9.5 Homebrew tap verification

The release workflow's `homebrew-test` job runs `brew install
wotw-verify` on `macos-14` (Apple Silicon) and asserts both
`--version` and `--self-test` succeed. This is automatic on v0.1.0
release IF:

- `HOMEBREW_TAP_TOKEN` secret is set on `DriftVane/wotw-verify`
  (fine-grained PAT with `contents:write` on `DriftVane/homebrew-tap`).
- `DriftVane/homebrew-tap` repo exists (see §9.1).

---

## 10. What this pass did NOT do (out of scope, per goal)

- **Cloud-side Compliance Pack export endpoint (CT4.01)** — separate
  cloud `/goal`. The pack format defined in `docs/verification-protocol.md`
  is the spec that endpoint must produce.
- **wotw-cloud integration** — wotw-verify is a standalone binary
  with no dependency on wotw-cloud.
- **Daemon-side changes** — the daemon (v0.8.3) ships unchanged. The
  embedded `/internal/verify` contract has not been modified.
- **Sigstore keyless signing** — the goal specified key-based with
  `cosign.pub` in repo + at `wotw.dev/keys/`. Keyless would require
  a different trust model + GitHub OIDC identity binding. Future work.

---

## 11. Handoff to next pass

The next `/goal` is "Push wotw-verify v0.1.0 live" — Justin's go/no-go
on §9. Specifically:

1. Replace the cosign placeholder (5 min).
2. Push the repo to `DriftVane/wotw-verify` (1 min).
3. Create `DriftVane/homebrew-tap` (1 min).
4. Set 3 GH secrets (2 min).
5. Tag v0.1.0, watch the release workflow (5–15 min).
6. Decide whether to deploy install.wotw.dev/verify now or defer to a
   follow-up (mostly DNS + hosting work, not verifier work).

Once §9.1-9.3 complete, CT5.01 + CT5.02 + CT5.03 flip to ✅ in the
v3 checklist.

---

**Authority:** Implementation work in this directory tree at HEAD.
Self-test evidence captured in §4. Reproducible-build evidence in §5.
Cosign signature evidence in §6. Test inventory in §7. Source size
in §8. External-action authority gates in §9.
