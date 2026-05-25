package provenance

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/DriftVane/wotw-verify/internal/canonical"
)

// GenesisChainHash is the previous_chain_hash carried by the first
// record in a chain. Matches GENESIS_HASH in src/provenance/hash.ts.
const GenesisChainHash = "0000000000000000000000000000000000000000000000000000000000000000"

// HMACKeyResolver looks up the symmetric HMAC key for a record.
//
// For G5-attested records (record.KeyID != nil) the resolver returns
// the workspace DEK (32 raw bytes). For G5-scaffolding or pre-G5
// records (record.KeyID == nil but record.HMAC != nil), the resolver
// may return a fallback key — typically the 4-tier resolution the
// daemon uses (env var > derived-from-tenant > undefined). For
// pre-G5-attestation records (record.HMAC == nil), the resolver is
// never called.
//
// Returning (nil, nil) signals "no key available for this record" —
// the verifier treats this as an attestation failure UNLESS the chain
// is being walked in non-strict mode (in which case the record is
// flagged as unattested but the chain may still verify overall).
type HMACKeyResolver interface {
	ResolveByID(keyID string) (key []byte, state string, err error)
	Fallback() (key []byte, err error)
}

// NoopResolver returns (nil, nil) for every lookup. Useful when the
// caller knows the chain has no HMAC attestation OR wants to verify
// only the chain-hash linkage (no key custody required).
type NoopResolver struct{}

// ResolveByID always returns (nil, "", nil).
func (NoopResolver) ResolveByID(string) ([]byte, string, error) { return nil, "", nil }

// Fallback always returns (nil, nil).
func (NoopResolver) Fallback() ([]byte, error) { return nil, nil }

// RecordError is a single per-record verification failure.
type RecordError struct {
	Seq    int    `json:"seq"`
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// RecordStatus carries per-record attestation outcomes (used in mixed
// mode where some records have HMAC and others don't).
type RecordStatus struct {
	Seq               int    `json:"seq"`
	ID                string `json:"id"`
	IDOK              bool   `json:"id_ok"`
	ChainHashOK       bool   `json:"chain_hash_ok"`
	LinkageOK         bool   `json:"linkage_ok"`
	HMACPresent       bool   `json:"hmac_present"`
	HMACOK            bool   `json:"hmac_ok,omitempty"`
	HMACKeyID         string `json:"hmac_key_id,omitempty"`
	HMACKeyState      string `json:"hmac_key_state,omitempty"`
	AttestationStatus string `json:"attestation_status"` // attested | unattested | failed
}

// VerifyOptions configures chain verification.
type VerifyOptions struct {
	// Resolver looks up HMAC keys by record.KeyID, or the fallback
	// single-key resolution for records without KeyID. Required when
	// any record in the chain carries an HMAC.
	Resolver HMACKeyResolver

	// Strict refuses to verify any chain that contains pre-G5-attestation
	// records (HMAC absent). When false (default), pre-G5 records are
	// reported as "unattested" but do not fail overall verification.
	Strict bool
}

// VerifyResult is the structured outcome of a chain walk.
type VerifyResult struct {
	OK              bool           `json:"ok"`
	TotalRecords    int            `json:"total_records"`
	VerifiedRecords int            `json:"verified_records"`
	Errors          []RecordError  `json:"errors"`
	Statuses        []RecordStatus `json:"statuses,omitempty"`
}

// ReadChainJSONL reads provenance records from a JSONL stream. Blank
// lines are skipped; lines that fail to parse are reported as errors
// (one per line) but parsing continues to the next.
func ReadChainJSONL(r io.Reader) ([]*Record, []error) {
	var records []*Record
	var errs []error
	scan := bufio.NewScanner(r)
	// chain.jsonl lines can be ~2KB each for typical ingest records
	// but the daemon doesn't cap line length; raise the buffer ceiling
	// generously.
	scan.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(line) == 0 || isOnlyWhitespace(line) {
			continue
		}
		rec, err := ParseRecord(line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		records = append(records, rec)
	}
	if err := scan.Err(); err != nil {
		errs = append(errs, fmt.Errorf("scan: %w", err))
	}
	return records, errs
}

func isOnlyWhitespace(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

// Verify walks records in seq order and validates the chain.
//
// Each record is checked for:
//   - seq strict-increment from 1
//   - previous_id matches prior record's id (or null at start)
//   - previous_chain_hash matches prior record's chain_hash (or GENESIS at start)
//   - id == sha256(canonicalJson(payload))
//   - chain_hash == sha256(previous_chain_hash + id)
//   - HMAC (when present) verifies under the resolved key
//
// Records must be in seq order. ReadChainJSONL returns them in file
// order, which mirrors the daemon's append-only write order.
func Verify(records []*Record, opts VerifyOptions) VerifyResult {
	res := VerifyResult{
		TotalRecords: len(records),
		Statuses:     make([]RecordStatus, 0, len(records)),
	}
	if opts.Resolver == nil {
		opts.Resolver = NoopResolver{}
	}

	prevChainHash := GenesisChainHash
	var prevID *string
	expectedSeq := 1

	for _, r := range records {
		status := RecordStatus{
			Seq:               r.Seq,
			ID:                r.ID,
			IDOK:              true,
			ChainHashOK:       true,
			LinkageOK:         true,
			AttestationStatus: "unattested",
		}

		if r.Seq != expectedSeq {
			res.Errors = append(res.Errors, RecordError{
				Seq:    r.Seq,
				ID:     r.ID,
				Reason: fmt.Sprintf("seq mismatch: expected %d, got %d", expectedSeq, r.Seq),
			})
			status.LinkageOK = false
		}

		// previous_id linkage
		got := derefOrNull(r.PreviousID)
		want := derefOrNull(prevID)
		if got != want {
			res.Errors = append(res.Errors, RecordError{
				Seq:    r.Seq,
				ID:     r.ID,
				Reason: fmt.Sprintf("previous_id mismatch: expected %s, got %s", want, got),
			})
			status.LinkageOK = false
		}

		if r.PreviousChainHash != prevChainHash {
			res.Errors = append(res.Errors, RecordError{
				Seq:    r.Seq,
				ID:     r.ID,
				Reason: fmt.Sprintf("previous_chain_hash mismatch: expected %s, got %s", prevChainHash, r.PreviousChainHash),
			})
			status.LinkageOK = false
		}

		// Canonical id recompute
		expectedID, err := canonical.SHA256Hex(r.CanonicalPayload())
		if err != nil {
			res.Errors = append(res.Errors, RecordError{
				Seq:    r.Seq,
				ID:     r.ID,
				Reason: fmt.Sprintf("canonical encode: %v", err),
			})
			status.IDOK = false
		} else if expectedID != r.ID {
			res.Errors = append(res.Errors, RecordError{
				Seq:    r.Seq,
				ID:     r.ID,
				Reason: fmt.Sprintf("id hash mismatch: expected %s, got %s", expectedID, r.ID),
			})
			status.IDOK = false
		}

		// Chain hash recompute (uses the record's STORED id — if id was
		// tampered the id check above already fired)
		expectedChainHash := canonical.SHA256HexString(r.PreviousChainHash + r.ID)
		if expectedChainHash != r.ChainHash {
			res.Errors = append(res.Errors, RecordError{
				Seq:    r.Seq,
				ID:     r.ID,
				Reason: fmt.Sprintf("chain_hash mismatch: expected %s, got %s", expectedChainHash, r.ChainHash),
			})
			status.ChainHashOK = false
		}

		// HMAC verification
		if r.HMAC != nil {
			status.HMACPresent = true
			if err := verifyHMAC(r, opts.Resolver, &status); err != nil {
				res.Errors = append(res.Errors, RecordError{
					Seq:    r.Seq,
					ID:     r.ID,
					Reason: err.Error(),
				})
				status.HMACOK = false
			} else {
				status.HMACOK = true
			}
		} else if opts.Strict {
			res.Errors = append(res.Errors, RecordError{
				Seq:    r.Seq,
				ID:     r.ID,
				Reason: "record has no hmac field (pre-G5 attestation) and strict mode is set",
			})
		}

		// Final per-record attestation classification. Order matters:
		// any structural failure overrides the HMAC outcome.
		switch {
		case !status.IDOK || !status.ChainHashOK || !status.LinkageOK:
			status.AttestationStatus = "failed"
		case status.HMACPresent && !status.HMACOK:
			status.AttestationStatus = "failed"
		case status.HMACPresent && status.HMACOK:
			status.AttestationStatus = "attested"
		default:
			status.AttestationStatus = "unattested"
		}

		res.Statuses = append(res.Statuses, status)

		prevChainHash = r.ChainHash
		idCopy := r.ID
		prevID = &idCopy
		expectedSeq = r.Seq + 1
	}

	res.VerifiedRecords = res.TotalRecords - countSeqsWithErrors(res.Errors)
	res.OK = len(res.Errors) == 0
	return res
}

func countSeqsWithErrors(errs []RecordError) int {
	if len(errs) == 0 {
		return 0
	}
	seen := make(map[int]struct{}, len(errs))
	for _, e := range errs {
		seen[e.Seq] = struct{}{}
	}
	return len(seen)
}

func verifyHMAC(r *Record, resolver HMACKeyResolver, status *RecordStatus) error {
	var key []byte
	var state string
	var resolveErr error

	if r.KeyID != nil {
		key, state, resolveErr = resolver.ResolveByID(*r.KeyID)
		status.HMACKeyID = *r.KeyID
		status.HMACKeyState = state
		if resolveErr != nil {
			return fmt.Errorf("hmac key lookup failed for key_id=%s: %w", *r.KeyID, resolveErr)
		}
		if key == nil {
			return fmt.Errorf("hmac key_id=%s not found by resolver", *r.KeyID)
		}
	} else {
		key, resolveErr = resolver.Fallback()
		if resolveErr != nil {
			return fmt.Errorf("hmac fallback key resolution failed: %w", resolveErr)
		}
		if key == nil {
			return fmt.Errorf("record has hmac but no key_id, and no fallback key available")
		}
	}

	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(r.HMACInput()); err != nil {
		return fmt.Errorf("hmac write: %w", err)
	}
	expected := mac.Sum(nil)

	stored, err := hex.DecodeString(*r.HMAC)
	if err != nil {
		return fmt.Errorf("hmac hex decode: %w", err)
	}
	if subtle.ConstantTimeCompare(stored, expected) != 1 {
		desc := "fallback"
		if r.KeyID != nil {
			desc = fmt.Sprintf("key_id=%s state=%s", shortID(*r.KeyID), state)
		}
		return fmt.Errorf("hmac mismatch (%s)", desc)
	}
	return nil
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func derefOrNull(p *string) string {
	if p == nil {
		return "null"
	}
	return *p
}
