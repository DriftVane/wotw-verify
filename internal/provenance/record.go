// Package provenance models the on-disk shape of a wotw provenance
// record and verifies hash-chain integrity.
//
// The daemon (TypeScript, src/provenance/chain.ts) writes one JSON
// object per line to a `chain.jsonl` file. Each record carries a
// canonical SHA-256 id, a chain hash linking it to its predecessor, and
// optionally an HMAC-SHA256 attestation under a workspace key.
//
// We parse the raw JSON into a Go-native shape that preserves the
// presence/absence distinction the daemon's `if (x !== undefined)`
// conditional inclusion relies on. Without that, canonical-payload
// recompute would be ambiguous for nullable fields (metadata,
// tenant_id).
package provenance

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Record is the verifier's view of one provenance record.
//
// Fields map to ProvenanceRecord in watcher-on-the-wall src/utils/types.ts.
// We keep `Raw` alongside so we can faithfully reproduce the daemon's
// canonical-payload conditional-inclusion behavior — a field absent
// from the source JSON must stay absent from the recomputed payload.
type Record struct {
	ID                  string            `json:"id"`
	Seq                 int               `json:"seq"`
	Timestamp           string            `json:"timestamp"`
	Type                string            `json:"type"`
	SourceFiles         []string          `json:"source_files"`
	SourceHashes        []string          `json:"source_hashes"`
	PromptHash          string            `json:"prompt_hash"`
	ModelID             string            `json:"model_id"`
	ResponseHash        string            `json:"response_hash"`
	WikiFilesWritten    []string          `json:"wiki_files_written"`
	WikiFileHashesAfter map[string]string `json:"wiki_file_hashes_after"`
	PreviousID          *string           `json:"previous_id"`
	PreviousChainHash   string            `json:"previous_chain_hash"`
	ChainHash           string            `json:"chain_hash"`

	// Optional, canonical-payload-INCLUDED.
	Metadata map[string]any `json:"metadata,omitempty"`
	TenantID *string        `json:"tenant_id,omitempty"`

	// Optional, canonical-payload-EXCLUDED (canonical-payload-exclusion
	// pattern — see PASS-018-G5-CLOSURE.md and project-provenance-compat
	// memory).
	HMAC                 *string  `json:"hmac,omitempty"`
	KeyID                *string  `json:"key_id,omitempty"`
	FactHashesAdded      []string `json:"fact_hashes_added,omitempty"`
	FactHashesSuperseded []string `json:"fact_hashes_superseded,omitempty"`
	MerkleRoot           *string  `json:"merkle_root,omitempty"`

	// Raw preserves the original parsed map so canonical-payload
	// recomputation can honor the daemon's "include iff present"
	// conditional rules.
	Raw map[string]any `json:"-"`
}

// ParseRecord decodes a single JSONL line into a Record.
//
// Returns an error if the JSON is malformed or required fields are
// missing.
func ParseRecord(line []byte) (*Record, error) {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	required := []string{
		"id", "seq", "timestamp", "type",
		"source_files", "source_hashes",
		"prompt_hash", "model_id", "response_hash",
		"wiki_files_written", "wiki_file_hashes_after",
		"previous_id", "previous_chain_hash", "chain_hash",
	}
	for _, k := range required {
		if _, ok := raw[k]; !ok {
			return nil, fmt.Errorf("missing required field %q", k)
		}
	}

	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-marshal: %w", err)
	}
	rec := &Record{Raw: raw}
	if err := json.Unmarshal(b, rec); err != nil {
		return nil, fmt.Errorf("decode record: %w", err)
	}
	return rec, nil
}

// CanonicalPayload returns the field-set the daemon uses to compute
// `id = sha256(canonicalJson(payload))`. Must exactly match the
// daemon's append()/verify() payload construction in chain.ts.
//
// Includes everything in Raw EXCEPT canonical-payload-excluded fields,
// AND only when present in the source record. Conditional-inclusion is
// critical: a record that omits `metadata` from JSON must not have a
// `metadata` key in the recomputed payload — even an empty one would
// change the hash.
func (r *Record) CanonicalPayload() map[string]any {
	excluded := map[string]struct{}{
		"id":                     {},
		"chain_hash":             {},
		"hmac":                   {},
		"key_id":                 {},
		"fact_hashes_added":      {},
		"fact_hashes_superseded": {},
		"merkle_root":            {},
	}
	out := make(map[string]any, len(r.Raw))
	for k, v := range r.Raw {
		if _, skip := excluded[k]; skip {
			continue
		}
		out[k] = v
	}
	return out
}

// HMACInput returns the byte sequence the daemon HMACs over:
// `${id}|${chain_hash}`. Returns nil if the record has no HMAC field.
func (r *Record) HMACInput() []byte {
	if r.HMAC == nil {
		return nil
	}
	return []byte(r.ID + "|" + r.ChainHash)
}
