// Package contract embeds the frozen /internal/verify contract from
// the daemon's PASS-018 closure document.
//
// The wotw-verify binary verifies provenance chains OFFLINE (no
// daemon, no /internal/verify HTTP endpoint). But the *verification
// algorithm* — canonical payload, chain hashing, HMAC attestation
// under workspace DEKs — is the one specified by PASS-018 §3-4.
//
// We embed that document at build time and assert its content hash
// in a unit test. If the document is ever modified (in this repo)
// without a corresponding bump of the expected hash, CI fails. This
// protects against silent drift between the verifier and the daemon's
// frozen contract.
package contract

import _ "embed"

// PASS018Markdown is the embedded copy of PASS-018-G5-CLOSURE.md.
// The byte sequence is the literal contents of the document as
// committed to this repo. See contract_test.go for the integrity hash.
//
//go:embed pass-018-g5-closure.md
var PASS018Markdown []byte

// PASS018Hash is the SHA-256 hex digest of PASS018Markdown computed at
// the time the document was last reviewed and accepted. If the embed
// content drifts from this hash, the integrity test in
// contract_test.go fails. To intentionally re-sync (e.g., after a
// daemon-side amendment that this verifier must follow), compute the
// new hash via:
//
//	sha256sum testdata/pass-018-g5-closure.md
//
// and update this constant in the SAME commit that re-syncs the
// embedded doc.
const PASS018Hash = "fffb6e9088f280ce24770e42f5fcc6863431cb6ff713c20f931f0441f9a0d67e" //nolint:gosec // SHA-256 hash of an embedded document, not a credential
