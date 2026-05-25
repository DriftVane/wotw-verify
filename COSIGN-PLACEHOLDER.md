# ⚠️ COSIGN PLACEHOLDER — REPLACE BEFORE v0.1.0

The `cosign.pub` currently committed in the repo root was generated
in a development environment during PASS-022 scaffolding. The matching
private key was created with a known placeholder password and MUST
NOT be used to sign any production release.

## Before tagging v0.1.0

```sh
# 1. Generate a fresh keypair with a strong password.
cosign generate-key-pair
# Prompts twice for a password. Use a high-entropy password and store
# it in a password manager — Bitwarden, 1Password, etc.

# This writes:
#   cosign.key  — encrypted private key, NEVER commit
#   cosign.pub  — public key, replaces the placeholder

# 2. Upload secrets to GitHub Actions.
gh secret set COSIGN_PRIVATE_KEY < cosign.key --repo DriftVane/wotw-verify
echo "<your password>" | gh secret set COSIGN_PASSWORD --repo DriftVane/wotw-verify

# 3. Commit the new cosign.pub.
git add cosign.pub
git rm COSIGN-PLACEHOLDER.md   # ← delete this file in the same commit
git commit -m "chore: cosign signing key (PASS-022)"
git push

# 4. Mirror the new public key at:
#    https://wotw.dev/keys/wotw-verify.pub
#    (deploy wotw-site or whichever target hosts wotw.dev/keys/)

# 5. Verify the round-trip.
goreleaser release --snapshot --clean --skip=publish
cd dist/
cosign verify-blob --key ../cosign.pub \
  --signature wotw-verify_0.0.1-next_linux_x86_64.tar.gz.sig \
  wotw-verify_0.0.1-next_linux_x86_64.tar.gz
# Verified OK

# 6. Tag and ship.
git tag v0.1.0 -m "Initial release"
git push origin v0.1.0
```

## What you'll find in the repo right now

- `cosign.pub` — placeholder public key. Safe to publish (it's a
  public key by definition) but signs nothing trustworthy.
- `cosign.key` — placeholder encrypted private key. SHOULD NOT have
  been committed (it's in `.gitignore`). If you find one in `git
  log`, treat that history as compromised and start fresh.

The release-process documentation in `docs/release-process.md` is
authoritative for steady-state operations. This file is only here to
remind you that the keypair shipping today is a placeholder.

Delete this file as part of the commit that replaces the placeholder.
