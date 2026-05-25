// Package selftest runs the 5 fixture scenarios from PASS-022 §A
// against the local verifier, in-process, with no external inputs.
//
// Exposed via `wotw-verify --self-test`, this lets a customer prove
// the binary they downloaded behaves correctly on a clean machine,
// without requiring a real Compliance Pack. The fixtures are built
// fresh in a temp directory each run (so the test exercises the full
// path: pack write → JSONL read → canonical recompute → HMAC verify),
// then deleted.
package selftest

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DriftVane/wotw-verify/internal/fixturegen"
	"github.com/DriftVane/wotw-verify/internal/verify"
)

// Result is the outcome of one self-test scenario.
type Result struct {
	Name        string
	WantVerdict string
	WantExit    int
	GotVerdict  string
	GotExit     int
	Errors      []string
}

// Pass returns true if the scenario produced its expected outcome.
func (r Result) Pass() bool {
	return r.GotVerdict == r.WantVerdict && r.GotExit == r.WantExit
}

// Run executes all 5 fixture scenarios. Returns a slice of Results
// AND a top-level error if anything in the harness (not the verifier)
// failed catastrophically.
func Run() ([]Result, error) {
	dir, err := os.MkdirTemp("", "wotw-verify-selftest-*")
	if err != nil {
		return nil, fmt.Errorf("make temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	scenarios := []func(string) (Result, error){
		runValidG5,
		runTamperedContent,
		runTamperedHMAC,
		runMidChainRotation,
		runPreG5BackwardCompat,
	}

	results := make([]Result, 0, len(scenarios))
	for _, s := range scenarios {
		r, err := s(dir)
		if err != nil {
			return results, err
		}
		results = append(results, r)
	}
	return results, nil
}

const selfTestTenant = "11111111-2222-3333-4444-555555555555"

func selfTestStartTime() time.Time {
	return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
}

func runValidG5(rootDir string) (Result, error) {
	dir := filepath.Join(rootDir, "a-valid-g5")
	kek := fixturegen.RandomBytes(32)
	dek := fixturegen.RandomBytes(32)
	keyID := "self-test-a"
	chain := fixturegen.BuildChain(selfTestTenant, []fixturegen.RecordSpec{
		g5Spec("ingest", "raw/a.md", "wiki/a.md", dek, keyID),
		g5Spec("ingest", "raw/b.md", "wiki/b.md", dek, keyID),
		g5Spec("ingest", "raw/c.md", "wiki/c.md", dek, keyID),
	}, selfTestStartTime())
	chain.Bundle = fixturegen.BundleFromDEKs(selfTestTenant, kek, chain.DEKs, nil)
	if err := fixturegen.WritePack(dir, chain); err != nil {
		return Result{Name: "valid_g5"}, err
	}
	r, _ := verify.Pack(dir, verify.Options{WorkspaceKEK: kek, IncludeStatuses: true})
	return collect("valid_g5", "verified", 0, r), nil
}

func runTamperedContent(rootDir string) (Result, error) {
	dir := filepath.Join(rootDir, "b-tampered-content")
	kek := fixturegen.RandomBytes(32)
	dek := fixturegen.RandomBytes(32)
	keyID := "self-test-b"
	chain := fixturegen.BuildChain(selfTestTenant, []fixturegen.RecordSpec{
		g5Spec("ingest", "raw/a.md", "wiki/a.md", dek, keyID),
		g5Spec("ingest", "raw/b.md", "wiki/b.md", dek, keyID),
		g5Spec("ingest", "raw/c.md", "wiki/c.md", dek, keyID),
	}, selfTestStartTime())
	chain.Bundle = fixturegen.BundleFromDEKs(selfTestTenant, kek, chain.DEKs, nil)
	// Tamper record 2's wiki_file_hashes_after value.
	hashes := chain.Records[1]["wiki_file_hashes_after"].(map[string]any)
	hashes["wiki/b.md"] = "tampered-by-selftest"
	if err := fixturegen.WritePack(dir, chain); err != nil {
		return Result{Name: "tampered_content"}, err
	}
	r, _ := verify.Pack(dir, verify.Options{WorkspaceKEK: kek, IncludeStatuses: true})
	return collect("tampered_content", "failed", 1, r), nil
}

func runTamperedHMAC(rootDir string) (Result, error) {
	dir := filepath.Join(rootDir, "c-tampered-hmac")
	kek := fixturegen.RandomBytes(32)
	dek := fixturegen.RandomBytes(32)
	keyID := "self-test-c"
	chain := fixturegen.BuildChain(selfTestTenant, []fixturegen.RecordSpec{
		g5Spec("ingest", "raw/a.md", "wiki/a.md", dek, keyID),
		g5Spec("ingest", "raw/b.md", "wiki/b.md", dek, keyID),
		g5Spec("ingest", "raw/c.md", "wiki/c.md", dek, keyID),
	}, selfTestStartTime())
	chain.Bundle = fixturegen.BundleFromDEKs(selfTestTenant, kek, chain.DEKs, nil)
	// Flip a hex digit in record 2's HMAC.
	hmac := chain.Records[1]["hmac"].(string)
	if hmac[0] == 'a' {
		chain.Records[1]["hmac"] = "b" + hmac[1:]
	} else {
		chain.Records[1]["hmac"] = "a" + hmac[1:]
	}
	if err := fixturegen.WritePack(dir, chain); err != nil {
		return Result{Name: "tampered_hmac"}, err
	}
	r, _ := verify.Pack(dir, verify.Options{WorkspaceKEK: kek, IncludeStatuses: true})
	return collect("tampered_hmac", "failed", 1, r), nil
}

func runMidChainRotation(rootDir string) (Result, error) {
	dir := filepath.Join(rootDir, "d-mid-chain-rotation")
	kek := fixturegen.RandomBytes(32)
	dekA := fixturegen.RandomBytes(32)
	dekB := fixturegen.RandomBytes(32)
	keyA := "self-test-d-old"
	keyB := "self-test-d-new"
	chain := fixturegen.BuildChain(selfTestTenant, []fixturegen.RecordSpec{
		g5Spec("ingest", "raw/a.md", "wiki/a.md", dekA, keyA),
		g5Spec("ingest", "raw/b.md", "wiki/b.md", dekA, keyA),
		g5Spec("ingest", "raw/c.md", "wiki/c.md", dekB, keyB),
		g5Spec("ingest", "raw/d.md", "wiki/d.md", dekB, keyB),
	}, selfTestStartTime())
	chain.Bundle = fixturegen.BundleFromDEKs(selfTestTenant, kek, chain.DEKs, map[string]string{
		keyA: "rotating",
		keyB: "active",
	})
	if err := fixturegen.WritePack(dir, chain); err != nil {
		return Result{Name: "mid_chain_rotation"}, err
	}
	r, _ := verify.Pack(dir, verify.Options{WorkspaceKEK: kek, IncludeStatuses: true})
	return collect("mid_chain_rotation", "verified", 0, r), nil
}

func runPreG5BackwardCompat(rootDir string) (Result, error) {
	dir := filepath.Join(rootDir, "e-pre-g5-compat")
	chain := fixturegen.BuildChain("", []fixturegen.RecordSpec{
		preG5Spec("ingest", "raw/a.md", "wiki/a.md"),
		preG5Spec("ingest", "raw/b.md", "wiki/b.md"),
		preG5Spec("ingest", "raw/c.md", "wiki/c.md"),
	}, selfTestStartTime())
	// No bundle.
	if err := fixturegen.WritePack(dir, chain); err != nil {
		return Result{Name: "pre_g5_backward_compat"}, err
	}
	r, _ := verify.Pack(dir, verify.Options{IncludeStatuses: true})
	return collect("pre_g5_backward_compat", "verified_with_unattested_records", 0, r), nil
}

func g5Spec(typ, source, wiki string, dek []byte, keyID string) fixturegen.RecordSpec {
	return fixturegen.RecordSpec{
		Type:                typ,
		SourceFiles:         []string{source},
		SourceHashes:        []string{shortHash(source)},
		PromptHash:          "p-" + shortHash(source),
		ModelID:             "claude-haiku-4-5",
		ResponseHash:        "r-" + shortHash(source),
		WikiFilesWritten:    []string{wiki},
		WikiFileHashesAfter: map[string]string{wiki: shortHash(wiki)},
		TenantID:            selfTestTenant,
		DEK:                 dek,
		KeyID:               keyID,
	}
}

func preG5Spec(typ, source, wiki string) fixturegen.RecordSpec {
	return fixturegen.RecordSpec{
		Type:                typ,
		SourceFiles:         []string{source},
		SourceHashes:        []string{shortHash(source)},
		PromptHash:          "p-" + shortHash(source),
		ModelID:             "claude-haiku-4-5",
		ResponseHash:        "r-" + shortHash(source),
		WikiFilesWritten:    []string{wiki},
		WikiFileHashesAfter: map[string]string{wiki: shortHash(wiki)},
	}
}

func shortHash(s string) string {
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		out[i] = "0123456789abcdef"[(int(s[i%len(s)])+i*7)%16]
	}
	return string(out)
}

func collect(name, wantVerdict string, wantExit int, r *verify.Report) Result {
	res := Result{
		Name:        name,
		WantVerdict: wantVerdict,
		WantExit:    wantExit,
	}
	if r != nil {
		res.GotVerdict = r.Verdict
		res.GotExit = r.ExitCode
		for _, e := range r.Errors {
			res.Errors = append(res.Errors, fmt.Sprintf("seq=%d %s", e.Seq, e.Reason))
		}
	}
	return res
}
