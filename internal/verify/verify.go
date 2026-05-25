// Package verify is the top-level verifier — given a pack path and
// optional workspace KEK, it returns a structured Report.
package verify

import (
	"fmt"
	"io"
	"time"

	"github.com/DriftVane/wotw-verify/internal/keys"
	"github.com/DriftVane/wotw-verify/internal/pack"
	"github.com/DriftVane/wotw-verify/internal/provenance"
)

// Report is the consolidated outcome of verifying a Compliance Pack.
//
// JSON shape matches what wotw-verify --json produces. Stable across
// minor versions; new fields may be added with omitempty but never
// renamed or removed without a major version bump.
type Report struct {
	Version          string                    `json:"version"`
	Tool             string                    `json:"tool"`
	PackPath         string                    `json:"pack_path"`
	Verdict          string                    `json:"verdict"`
	ExitCode         int                       `json:"exit_code"`
	ChainOK          bool                      `json:"chain_ok"`
	WorkspaceID      string                    `json:"workspace_id,omitempty"`
	TotalRecords     int                       `json:"total_records"`
	VerifiedRecords  int                       `json:"verified_records"`
	AttestedRecords  int                       `json:"attested_records"`
	UnattestedTotal  int                       `json:"unattested_total"`
	FailedRecords    int                       `json:"failed_records"`
	Errors           []provenance.RecordError  `json:"errors,omitempty"`
	Statuses         []provenance.RecordStatus `json:"statuses,omitempty"`
	HMACKeysResolved int                       `json:"hmac_keys_resolved"`
	StrictMode       bool                      `json:"strict_mode"`
	DurationMS       int64                     `json:"duration_ms"`
	StartedAt        string                    `json:"started_at"`
}

// ToolVersion is stamped onto every Report. Set by ldflags at build time.
var ToolVersion = "dev"

// Options configures a verification run.
type Options struct {
	// WorkspaceKEK, if non-nil, is the 32-byte KEK used to decrypt
	// per-key DEKs in the pack's keys.json. Required when any chain
	// record carries an HMAC field AND a key_id.
	WorkspaceKEK []byte

	// Strict refuses to verify chains containing pre-G5-attestation
	// records (records with no hmac field). Default false.
	Strict bool

	// IncludeStatuses controls whether per-record status entries are
	// emitted in the Report. JSON output mode sets true.
	IncludeStatuses bool
}

// Pack verifies the pack at the given path under the given options.
func Pack(packPath string, opts Options) (*Report, error) {
	t0 := time.Now()
	report := &Report{
		Version:    "1",
		Tool:       "wotw-verify",
		PackPath:   packPath,
		StrictMode: opts.Strict,
		StartedAt:  t0.UTC().Format(time.RFC3339),
	}

	pk, err := pack.Open(packPath)
	if err != nil {
		report.Verdict = "malformed"
		report.ExitCode = 2
		report.DurationMS = time.Since(t0).Milliseconds()
		return report, fmt.Errorf("open pack: %w", err)
	}
	defer pk.Close()
	report.WorkspaceID = pk.Manifest.TenantID

	chainRC, err := pk.ChainJSONL()
	if err != nil {
		report.Verdict = "malformed"
		report.ExitCode = 2
		report.DurationMS = time.Since(t0).Milliseconds()
		return report, fmt.Errorf("read chain: %w", err)
	}
	defer chainRC.Close()

	records, readErrs := provenance.ReadChainJSONL(chainRC)
	if len(readErrs) > 0 {
		// Per-line parse errors degrade to verdict=malformed.
		report.Verdict = "malformed"
		report.ExitCode = 2
		report.DurationMS = time.Since(t0).Milliseconds()
		return report, joinErrors("chain.jsonl parse errors", readErrs)
	}

	resolver, keysResolved, err := buildResolver(pk, opts.WorkspaceKEK)
	if err != nil {
		report.Verdict = "malformed"
		report.ExitCode = 2
		report.DurationMS = time.Since(t0).Milliseconds()
		return report, fmt.Errorf("resolve workspace keys: %w", err)
	}
	report.HMACKeysResolved = keysResolved

	result := provenance.Verify(records, provenance.VerifyOptions{
		Resolver: resolver,
		Strict:   opts.Strict,
	})

	report.ChainOK = result.OK
	report.TotalRecords = result.TotalRecords
	report.VerifiedRecords = result.VerifiedRecords
	report.Errors = result.Errors
	if opts.IncludeStatuses {
		report.Statuses = result.Statuses
	}
	for _, s := range result.Statuses {
		switch s.AttestationStatus {
		case "attested":
			report.AttestedRecords++
		case "unattested":
			report.UnattestedTotal++
		case "failed":
			report.FailedRecords++
		}
	}

	switch {
	case result.OK && report.AttestedRecords == report.TotalRecords:
		report.Verdict = "verified"
		report.ExitCode = 0
	case result.OK && report.UnattestedTotal > 0 && !opts.Strict:
		report.Verdict = "verified_with_unattested_records"
		report.ExitCode = 0
	default:
		report.Verdict = "failed"
		report.ExitCode = 1
	}

	report.DurationMS = time.Since(t0).Milliseconds()
	return report, nil
}

func buildResolver(pk *pack.Pack, kek []byte) (provenance.HMACKeyResolver, int, error) {
	if !pk.HasKeys {
		// No keys.json in the pack — resolver is a no-op. Chains with
		// HMAC records will fail attestation but chain-hash linkage is
		// independent and can still be verified.
		return provenance.NoopResolver{}, 0, nil
	}
	rc, err := pk.KeysJSON()
	if err != nil {
		return nil, 0, fmt.Errorf("open keys.json: %w", err)
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return nil, 0, fmt.Errorf("read keys.json: %w", err)
	}
	bundle, err := keys.ParseBundle(raw)
	if err != nil {
		return nil, 0, err
	}
	return keys.NewResolver(bundle, kek), len(bundle.Keys), nil
}

func joinErrors(prefix string, errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return fmt.Errorf("%s: %w", prefix, errs[0])
	}
	return fmt.Errorf("%s: %d errors (first: %v)", prefix, len(errs), errs[0])
}
