package selftest

import "testing"

// TestRunAllPass runs the embedded self-test scenarios and asserts
// every one produces its expected verdict. This is the "5 embedded
// fixtures with expected verdict" gate from PASS-022 §A.
func TestRunAllPass(t *testing.T) {
	results, err := Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("got %d scenarios, want 5", len(results))
	}
	for _, r := range results {
		if !r.Pass() {
			t.Errorf("scenario %s: got verdict=%q exit=%d, want %q exit=%d (errors: %v)",
				r.Name, r.GotVerdict, r.GotExit, r.WantVerdict, r.WantExit, r.Errors)
		}
	}
}
