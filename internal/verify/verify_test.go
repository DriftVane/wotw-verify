package verify_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/3030-Labs/wotw-verify/internal/fixturegen"
	"github.com/3030-Labs/wotw-verify/internal/keys"
	"github.com/3030-Labs/wotw-verify/internal/verify"
)

// The 5 fixture scenarios named in PASS-022 goal:
//
//  (a) valid G5-attested      → verdict "verified", exit 0
//  (b) tampered content       → verdict "failed",   exit 1
//  (c) tampered HMAC          → verdict "failed",   exit 1
//  (d) mid-chain rotation     → verdict "verified", exit 0
//  (e) pre-G5 backward-compat → verdict "verified_with_unattested_records",
//                               exit 0 (non-strict)
//                             → verdict "failed", exit 1 (strict)

const fixtureTenant = "11111111-2222-3333-4444-555555555555"

func startTime() time.Time {
	return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
}

func makeKEK(t *testing.T) []byte {
	t.Helper()
	return fixturegen.RandomBytes(32)
}

func makeDEK(t *testing.T) []byte {
	t.Helper()
	return fixturegen.RandomBytes(32)
}

func writeKEKFile(t *testing.T, dir string, kek []byte) string {
	t.Helper()
	path := filepath.Join(dir, "kek.bin")
	// keys.ParseKEK accepts base64 or hex; write hex for visibility.
	if err := writeHex(path, kek); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFixtureA_ValidG5Attested(t *testing.T) {
	dir := t.TempDir()
	kek := makeKEK(t)
	dek := makeDEK(t)
	keyID := "fixture-key-a"

	chain := fixturegen.BuildChain(fixtureTenant, []fixturegen.RecordSpec{
		newG5Spec("ingest", "raw/a.md", "wiki/a.md", dek, keyID),
		newG5Spec("ingest", "raw/b.md", "wiki/b.md", dek, keyID),
		newG5Spec("ingest", "raw/c.md", "wiki/c.md", dek, keyID),
	}, startTime())
	chain.Bundle = fixturegen.BundleFromDEKs(fixtureTenant, kek, chain.DEKs, nil)

	packDir := filepath.Join(dir, "pack")
	mustWritePack(t, packDir, chain)
	kekPath := writeKEKFile(t, dir, kek)

	r, err := verify.Pack(packDir, verify.Options{
		WorkspaceKEK:    mustLoadKEK(t, kekPath),
		IncludeStatuses: true,
	})
	mustNoError(t, err)

	wantExit(t, r, 0)
	wantVerdict(t, r, "verified")
	if r.AttestedRecords != 3 {
		t.Errorf("attested=%d, want 3", r.AttestedRecords)
	}
	if r.UnattestedTotal != 0 || r.FailedRecords != 0 {
		t.Errorf("unattested=%d failed=%d, want 0/0", r.UnattestedTotal, r.FailedRecords)
	}
}

func TestFixtureB_TamperedContent(t *testing.T) {
	dir := t.TempDir()
	kek := makeKEK(t)
	dek := makeDEK(t)
	keyID := "fixture-key-b"

	chain := fixturegen.BuildChain(fixtureTenant, []fixturegen.RecordSpec{
		newG5Spec("ingest", "raw/a.md", "wiki/a.md", dek, keyID),
		newG5Spec("ingest", "raw/b.md", "wiki/b.md", dek, keyID),
		newG5Spec("ingest", "raw/c.md", "wiki/c.md", dek, keyID),
	}, startTime())
	chain.Bundle = fixturegen.BundleFromDEKs(fixtureTenant, kek, chain.DEKs, nil)

	// Tamper: flip a wiki_file_hashes_after value in record 2.
	rec := chain.Records[1]
	hashes := rec["wiki_file_hashes_after"].(map[string]any)
	hashes["wiki/b.md"] = "tampered-content-hash"

	packDir := filepath.Join(dir, "pack")
	mustWritePack(t, packDir, chain)
	kekPath := writeKEKFile(t, dir, kek)

	r, err := verify.Pack(packDir, verify.Options{
		WorkspaceKEK:    mustLoadKEK(t, kekPath),
		IncludeStatuses: true,
	})
	mustNoError(t, err)

	t.Logf("report: verdict=%s exit=%d total=%d verified=%d attested=%d unattested=%d failed=%d",
		r.Verdict, r.ExitCode, r.TotalRecords, r.VerifiedRecords, r.AttestedRecords, r.UnattestedTotal, r.FailedRecords)
	for _, e := range r.Errors {
		t.Logf("  error: seq=%d id=%s reason=%s", e.Seq, e.ID, e.Reason)
	}
	for _, s := range r.Statuses {
		t.Logf("  status: seq=%d att=%s id_ok=%v chain_ok=%v hmac_present=%v hmac_ok=%v",
			s.Seq, s.AttestationStatus, s.IDOK, s.ChainHashOK, s.HMACPresent, s.HMACOK)
	}
	wantExit(t, r, 1)
	wantVerdict(t, r, "failed")
	if len(r.Errors) < 1 {
		t.Errorf("expected at least 1 chain error, got %d", len(r.Errors))
	}
}

func TestFixtureC_TamperedHMAC(t *testing.T) {
	dir := t.TempDir()
	kek := makeKEK(t)
	dek := makeDEK(t)
	keyID := "fixture-key-c"

	chain := fixturegen.BuildChain(fixtureTenant, []fixturegen.RecordSpec{
		newG5Spec("ingest", "raw/a.md", "wiki/a.md", dek, keyID),
		newG5Spec("ingest", "raw/b.md", "wiki/b.md", dek, keyID),
		newG5Spec("ingest", "raw/c.md", "wiki/c.md", dek, keyID),
	}, startTime())
	chain.Bundle = fixturegen.BundleFromDEKs(fixtureTenant, kek, chain.DEKs, nil)

	// Tamper: flip the first hex char of record 2's hmac field.
	rec := chain.Records[1]
	hmac := rec["hmac"].(string)
	if hmac[0] == 'a' {
		rec["hmac"] = "b" + hmac[1:]
	} else {
		rec["hmac"] = "a" + hmac[1:]
	}

	packDir := filepath.Join(dir, "pack")
	mustWritePack(t, packDir, chain)
	kekPath := writeKEKFile(t, dir, kek)

	r, err := verify.Pack(packDir, verify.Options{
		WorkspaceKEK:    mustLoadKEK(t, kekPath),
		IncludeStatuses: true,
	})
	mustNoError(t, err)

	wantExit(t, r, 1)
	wantVerdict(t, r, "failed")
	if r.FailedRecords != 1 {
		t.Errorf("expected exactly 1 failed record (HMAC-only tamper), got %d", r.FailedRecords)
	}
	// id + chain_hash + linkage all still valid for records 1, 3.
	if r.VerifiedRecords < 2 {
		t.Errorf("expected at least 2 records still pass linkage, got %d", r.VerifiedRecords)
	}
}

func TestFixtureD_MidChainRotation(t *testing.T) {
	dir := t.TempDir()
	kek := makeKEK(t)
	dekA := makeDEK(t)
	dekB := makeDEK(t)
	keyA := "fixture-key-d-old"
	keyB := "fixture-key-d-new"

	// Records 1+2 signed under key A. Records 3+4 signed under key B.
	// This models a mid-chain DEK rotation. Both keys present in
	// keys.json; key A in "rotating" state, key B "active".
	chain := fixturegen.BuildChain(fixtureTenant, []fixturegen.RecordSpec{
		newG5Spec("ingest", "raw/a.md", "wiki/a.md", dekA, keyA),
		newG5Spec("ingest", "raw/b.md", "wiki/b.md", dekA, keyA),
		newG5Spec("ingest", "raw/c.md", "wiki/c.md", dekB, keyB),
		newG5Spec("ingest", "raw/d.md", "wiki/d.md", dekB, keyB),
	}, startTime())
	chain.Bundle = fixturegen.BundleFromDEKs(fixtureTenant, kek, chain.DEKs, map[string]string{
		keyA: "rotating",
		keyB: "active",
	})

	packDir := filepath.Join(dir, "pack")
	mustWritePack(t, packDir, chain)
	kekPath := writeKEKFile(t, dir, kek)

	r, err := verify.Pack(packDir, verify.Options{
		WorkspaceKEK:    mustLoadKEK(t, kekPath),
		IncludeStatuses: true,
	})
	mustNoError(t, err)

	wantExit(t, r, 0)
	wantVerdict(t, r, "verified")
	if r.AttestedRecords != 4 {
		t.Errorf("attested=%d, want 4", r.AttestedRecords)
	}
	// Confirm both keys participated.
	usedA, usedB := false, false
	for _, s := range r.Statuses {
		if s.HMACKeyID == keyA {
			usedA = true
		}
		if s.HMACKeyID == keyB {
			usedB = true
		}
	}
	if !usedA || !usedB {
		t.Errorf("expected both keys in attestation: keyA=%v keyB=%v", usedA, usedB)
	}
}

func TestFixtureE_PreG5_BackwardCompat(t *testing.T) {
	dir := t.TempDir()

	// Pre-G5 records have no HMAC field at all. The daemon constructs
	// these when no fallback hmacKey is resolvable (no KEK, no
	// WOTW_PROVENANCE_HMAC_KEY env, no tenant_id-derive).
	chain := fixturegen.BuildChain("", []fixturegen.RecordSpec{
		newPreG5Spec("ingest", "raw/a.md", "wiki/a.md"),
		newPreG5Spec("ingest", "raw/b.md", "wiki/b.md"),
		newPreG5Spec("ingest", "raw/c.md", "wiki/c.md"),
	}, startTime())
	// No keys.json — pre-G5 daemons didn't produce one.

	packDir := filepath.Join(dir, "pack")
	mustWritePack(t, packDir, chain)

	// Non-strict mode: verifier reports "verified_with_unattested_records"
	r, err := verify.Pack(packDir, verify.Options{IncludeStatuses: true})
	mustNoError(t, err)
	wantExit(t, r, 0)
	wantVerdict(t, r, "verified_with_unattested_records")
	if r.UnattestedTotal != 3 {
		t.Errorf("unattested=%d, want 3", r.UnattestedTotal)
	}

	// Strict mode: same chain → failed.
	rs, err := verify.Pack(packDir, verify.Options{Strict: true, IncludeStatuses: true})
	mustNoError(t, err)
	wantExit(t, rs, 1)
	wantVerdict(t, rs, "failed")
}

func newG5Spec(typ, source, wiki string, dek []byte, keyID string) fixturegen.RecordSpec {
	return fixturegen.RecordSpec{
		Type:                typ,
		SourceFiles:         []string{source},
		SourceHashes:        []string{shortHash(source)},
		PromptHash:          "p-" + shortHash(source),
		ModelID:             "claude-haiku-4-5",
		ResponseHash:        "r-" + shortHash(source),
		WikiFilesWritten:    []string{wiki},
		WikiFileHashesAfter: map[string]string{wiki: shortHash(wiki)},
		TenantID:            fixtureTenant,
		DEK:                 dek,
		KeyID:               keyID,
	}
}

func newPreG5Spec(typ, source, wiki string) fixturegen.RecordSpec {
	return fixturegen.RecordSpec{
		Type:                typ,
		SourceFiles:         []string{source},
		SourceHashes:        []string{shortHash(source)},
		PromptHash:          "p-" + shortHash(source),
		ModelID:             "claude-haiku-4-5",
		ResponseHash:        "r-" + shortHash(source),
		WikiFilesWritten:    []string{wiki},
		WikiFileHashesAfter: map[string]string{wiki: shortHash(wiki)},
		// No TenantID, no DEK, no FallbackHMACKey → no hmac field.
	}
}

// shortHash returns a deterministic 16-char hex digest derived from s.
// Stand-in for the real per-content sha256 the daemon computes; we
// don't need real content hashes to test the chain verifier.
func shortHash(s string) string {
	h := []byte(s)
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		out[i] = "0123456789abcdef"[(int(h[i%len(h)])+i*7)%16]
	}
	return string(out)
}

func mustWritePack(t *testing.T, dir string, c *fixturegen.Chain) {
	t.Helper()
	if err := fixturegen.WritePack(dir, c); err != nil {
		t.Fatal(err)
	}
}

func mustNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustLoadKEK(t *testing.T, path string) []byte {
	t.Helper()
	k, err := keys.LoadKEKFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func wantExit(t *testing.T, r *verify.Report, want int) {
	t.Helper()
	if r.ExitCode != want {
		t.Errorf("exit code = %d, want %d (verdict=%q, errors=%v)", r.ExitCode, want, r.Verdict, r.Errors)
	}
}

func wantVerdict(t *testing.T, r *verify.Report, want string) {
	t.Helper()
	if r.Verdict != want {
		t.Errorf("verdict = %q, want %q", r.Verdict, want)
	}
}
