# Release process

This document describes how DriftVane cuts a `wotw-verify` release,
how the cosign signing key is managed, and how a third party can
independently verify a release was built reproducibly.

---

## Anatomy of a release

A `wotw-verify` release consists of:

1. A Git tag `vX.Y.Z` on `main`.
2. Cross-platform binaries (5 targets, see below) built reproducibly
   from that tag.
3. A SHA-256 checksums file covering every binary archive.
4. Cosign signatures (`.sig` files) for every archive AND the
   checksums file.
5. A GitHub Release containing the above.
6. An updated Homebrew formula in `DriftVane/homebrew-tap`.
7. A `cosign.pub` file in the repo root (rotation point — see §5).

---

## 1. Cutting a release

### 1.1 Pre-release checklist

```sh
# All tests green
go test ./... -race

# Lint clean
golangci-lint run ./...

# Reproducible build sanity check (compare hashes)
goreleaser build --snapshot --clean --single-target
sha256sum dist/wotw-verify_linux_amd64_v1/wotw-verify > /tmp/h1

rm -rf dist
goreleaser build --snapshot --clean --single-target
sha256sum dist/wotw-verify_linux_amd64_v1/wotw-verify > /tmp/h2

diff /tmp/h1 /tmp/h2   # MUST be empty

# Embedded self-test passes on the built binary
./dist/wotw-verify_linux_amd64_v1/wotw-verify --self-test

# Documentation up to date
grep -i "TODO\|XXX\|FIXME" docs/  # should be empty for release
```

If any of these fail, **halt** and fix before tagging.

### 1.2 Tag + push

```sh
git tag -a v0.1.0 -m "Initial release"
git push origin v0.1.0
```

The `release` GitHub Action workflow fires on tag push and runs:

1. `go test ./...` (must pass).
2. `goreleaser release --clean` which:
   - Cross-compiles for 5 platforms.
   - Archives each (`.tar.gz` / `.zip`).
   - Computes SHA-256 checksums.
   - Cosign-signs every archive + checksums file.
   - Uploads to GitHub Releases.
   - Opens a PR against `DriftVane/homebrew-tap` updating the formula.

The workflow requires three secrets:

| Secret             | Contents                                                |
|--------------------|---------------------------------------------------------|
| `COSIGN_PRIVATE_KEY` | The contents of `cosign.key` (cosign-encrypted).      |
| `COSIGN_PASSWORD`  | The password used to encrypt `cosign.key`.              |
| `HOMEBREW_TAP_TOKEN` | A fine-grained PAT with `contents:write` on `homebrew-tap`. |

### 1.3 Post-release verification (mandatory)

After the release publishes:

```sh
# Download every artifact
gh release download v0.1.0 --repo DriftVane/wotw-verify --dir ./v0.1.0/

cd v0.1.0/

# Verify each archive's cosign signature
for f in wotw-verify_*.tar.gz wotw-verify_*.zip; do
  cosign verify-blob --key ../cosign.pub --signature "${f}.sig" "${f}" \
    || (echo "SIGNATURE INVALID: ${f}"; exit 1)
done

# Verify the checksums file's signature
cosign verify-blob --key ../cosign.pub \
  --signature wotw-verify_0.1.0_checksums.txt.sig \
  wotw-verify_0.1.0_checksums.txt

# Check every archive against the checksums
sha256sum -c wotw-verify_0.1.0_checksums.txt
```

If ANY step fails, the release MUST be deleted from GitHub Releases
and reissued. Do not leave a partial / corrupt release public.

---

## 2. Reproducible-build verification (third-party)

A third party can independently confirm a release was built
reproducibly from the tagged source:

```sh
# Check out the exact tag
git clone https://github.com/DriftVane/wotw-verify
cd wotw-verify
git checkout v0.1.0

# Rebuild with goreleaser
goreleaser build --clean --single-target

# Hash the locally-built binary
sha256sum dist/wotw-verify_linux_amd64_v1/wotw-verify

# Download and unpack the released binary for the same platform
gh release download v0.1.0 --pattern '*linux_x86_64*' \
  --repo DriftVane/wotw-verify
tar -xzf wotw-verify_0.1.0_linux_x86_64.tar.gz
sha256sum wotw-verify

# Hashes MUST match
```

Mismatches indicate either:

- A regression in our build reproducibility (toolchain version drift,
  build cache contamination) — file an issue.
- A compromised release artifact — initiate vulnerability response.

---

## 3. Cosign key generation (first-time setup)

```sh
# Generate a new cosign keypair. You will be prompted for a password
# that encrypts the private key.
cosign generate-key-pair

# Outputs:
#   cosign.key   — encrypted private key (DO NOT COMMIT)
#   cosign.pub   — public key (COMMIT to repo root)

# Add the encrypted private key to GitHub Actions secrets:
gh secret set COSIGN_PRIVATE_KEY < cosign.key \
  --repo DriftVane/wotw-verify

# Add the password as a secret too:
echo "$COSIGN_PASSWORD_VALUE" | gh secret set COSIGN_PASSWORD \
  --repo DriftVane/wotw-verify

# Commit and push the public key.
git add cosign.pub
git commit -m "Initial cosign public key"
git push

# Mirror the public key at wotw.dev/keys/wotw-verify.pub
# (see your DNS / hosting provider's docs).
```

The private key (`cosign.key`) MUST NOT be checked into Git or shared
outside the release operator's local machine + the GitHub Actions
secret.

---

## 4. Verifying a release using only the published public key

A customer with no DriftVane affiliation can verify any release using
only the public key from one of:

- `https://github.com/DriftVane/wotw-verify/blob/main/cosign.pub`
- `https://wotw.dev/keys/wotw-verify.pub`

```sh
curl -fsSL https://wotw.dev/keys/wotw-verify.pub -o cosign.pub

# Pick a release artifact
gh release download v0.1.0 --pattern '*linux_x86_64*' \
  --repo DriftVane/wotw-verify

cosign verify-blob --key cosign.pub \
  --signature wotw-verify_0.1.0_linux_x86_64.tar.gz.sig \
  wotw-verify_0.1.0_linux_x86_64.tar.gz
# Verified OK
```

The install script at `install.wotw.dev/verify` does this
automatically: it downloads the binary, downloads the `.sig`, fetches
`cosign.pub` from the canonical URL, runs `cosign verify-blob`, and
only extracts if verification succeeds.

---

## 5. Rotating the cosign signing key

If the private key is suspected compromised, rotate IMMEDIATELY:

```sh
# 1. Generate a new keypair with a new password.
cosign generate-key-pair  # writes new cosign.key + cosign.pub

# 2. Update GitHub Actions secrets with the new private key + password.
gh secret set COSIGN_PRIVATE_KEY < cosign.key
echo "<new password>" | gh secret set COSIGN_PASSWORD

# 3. Commit the new cosign.pub.
git add cosign.pub
git commit -m "Rotate cosign signing key (incident YYYY-MM-DD)"
git push

# 4. Update wotw.dev/keys/wotw-verify.pub to the new public key.

# 5. Add a SECURITY notice to the next release notes naming the
#    rotation date so customers know to refresh their pinned key.
```

Historical releases signed under the old key REMAIN VALID under that
old key — `cosign.pub` rotation does not invalidate past signatures.
Customers who pinned the old key should add the new key to their
trust set rather than replacing it.

For incident response, see `docs/threat-model.md` § "Reporting a
vulnerability".

---

## 6. Homebrew tap

The release workflow opens a PR against `DriftVane/homebrew-tap`
updating `Formula/wotw-verify.rb` with the new version + URL +
SHA-256 of the macOS arm64 + x86_64 archives.

A maintainer reviews the PR and merges. From that point, `brew
upgrade wotw-verify` picks up the new release.

The Homebrew formula includes a `test do` block that runs
`wotw-verify --version` AND `wotw-verify --self-test`. If either
fails post-install, `brew test wotw-verify` exits non-zero.

---

## 7. Pre-release / RC tags

For pre-release tags (`v0.1.0-rc1`, etc.), GoReleaser marks the
release as a prerelease on GitHub (no Homebrew formula update). The
same cosign signing applies, so RC artifacts are still verifiable.

```sh
git tag v0.1.0-rc1 -m "Release candidate 1"
git push origin v0.1.0-rc1
```

---

## 8. Deleting a botched release

If a release goes out broken (failed gates, missing artifacts, wrong
content):

```sh
# Delete from GitHub
gh release delete v0.1.0 --yes --cleanup-tag --repo DriftVane/wotw-verify

# Move the tag locally
git tag -d v0.1.0
git push origin :v0.1.0

# Fix the issue, then re-tag.
```

**Do not re-use a tag** unless every consumer has fetched the broken
version. If anyone has downloaded it, the SHA-256 they have is no
longer trustworthy and you risk supply-chain confusion. Bump to
`v0.1.1` for the corrected release.
