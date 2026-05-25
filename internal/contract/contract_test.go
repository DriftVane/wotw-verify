package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestPASS018MarkdownIntegrity proves that the embedded contract
// document has not drifted from the version this verifier was built
// against. If this test fails, the contract document was edited
// without bumping PASS018Hash — either an unintentional drift (revert)
// OR an intentional re-sync (update PASS018Hash in the same commit).
func TestPASS018MarkdownIntegrity(t *testing.T) {
	if len(PASS018Markdown) == 0 {
		t.Fatal("embedded PASS018Markdown is empty")
	}
	sum := sha256.Sum256(PASS018Markdown)
	got := hex.EncodeToString(sum[:])
	if got != PASS018Hash {
		t.Errorf("embedded contract has drifted from PASS018Hash\n  got:  %s\n  want: %s\nIf this is intentional, update PASS018Hash in contract.go.",
			got, PASS018Hash)
	}
}

// TestPASS018ContractFrozen sanity-checks that the embedded markdown
// still describes the key contract surfaces our verifier consumes.
// Without these landmarks the verifier and the daemon's contract are
// suspiciously misaligned.
func TestPASS018ContractFrozen(t *testing.T) {
	doc := string(PASS018Markdown)
	mustContain(t, doc, "/internal/verify")
	mustContain(t, doc, "frozen")
	mustContain(t, doc, "HMAC")
	mustContain(t, doc, "excluded from canonical payload")
	mustContain(t, doc, "workspace_keys")
	mustContain(t, doc, "AES-256-GCM")
}

func mustContain(t *testing.T, doc, needle string) {
	t.Helper()
	if !strings.Contains(doc, needle) {
		t.Errorf("contract document missing expected landmark %q", needle)
	}
}
