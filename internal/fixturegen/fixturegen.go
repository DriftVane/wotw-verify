// Package fixturegen builds wotw Compliance Pack fixtures
// programmatically for verifier test scenarios.
//
// This is essentially a Go port of the daemon's ProvenanceChain.append()
// and KeyStore.provision() + the AES-256-GCM envelope. The intent is
// to produce packs that an in-the-wild daemon-produced pack should be
// byte-compatible with — but generated entirely Go-side so the tests
// have full control over tampering scenarios.
package fixturegen

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/DriftVane/wotw-verify/internal/canonical"
	"github.com/DriftVane/wotw-verify/internal/keys"
)

// Genesis matches GENESIS_HASH in the daemon.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// RecordSpec captures what a fixture wants to append. Mirrors
// ProvenanceAppendInput in the daemon plus optional G5 attestation.
type RecordSpec struct {
	Type                 string
	SourceFiles          []string
	SourceHashes         []string
	PromptHash           string
	ModelID              string
	ResponseHash         string
	WikiFilesWritten     []string
	WikiFileHashesAfter  map[string]string
	Metadata             map[string]any
	TenantID             string
	FactHashesAdded      []string
	FactHashesSuperseded []string

	// G5 attestation — if non-nil, sign with this DEK and stamp KeyID.
	DEK   []byte
	KeyID string
	// Fallback HMAC key (single-key path) — used when DEK is nil.
	FallbackHMACKey []byte
}

// Chain holds a programmatically-built chain plus a key bundle.
type Chain struct {
	WorkspaceID string
	Records     []map[string]any // raw maps preserve presence info
	Bundle      *keys.Bundle
	KEK         []byte
	// Plaintext DEKs, indexed by key_id (handy for tests that want to
	// re-sign tampered records under the same key).
	DEKs map[string][]byte
}

// BuildChain appends specs in order, computing canonical id + chain_hash
// + HMAC exactly as the daemon does. Returns the constructed Chain.
func BuildChain(workspaceID string, specs []RecordSpec, startAt time.Time) *Chain {
	chain := &Chain{
		WorkspaceID: workspaceID,
		DEKs:        make(map[string][]byte),
	}
	prevChainHash := Genesis
	var prevID *string
	for i, spec := range specs {
		ts := startAt.Add(time.Duration(i) * time.Second).UTC().Format("2006-01-02T15:04:05.000Z")
		payload := buildCanonicalPayload(i+1, ts, spec, prevID, prevChainHash)
		id, _ := canonical.SHA256Hex(payload)
		chainHash := canonical.SHA256HexString(prevChainHash + id)

		record := cloneMap(payload)
		record["id"] = id
		record["chain_hash"] = chainHash
		appendOptionalExcluded(record, spec, id, chainHash)

		chain.Records = append(chain.Records, record)
		if spec.DEK != nil {
			chain.DEKs[spec.KeyID] = spec.DEK
		}
		prevChainHash = chainHash
		idCopy := id
		prevID = &idCopy
	}
	return chain
}

func buildCanonicalPayload(seq int, ts string, spec RecordSpec, prevID *string, prevChainHash string) map[string]any {
	out := map[string]any{
		"seq":                    float64(seq),
		"timestamp":              ts,
		"type":                   spec.Type,
		"source_files":           toAnySlice(spec.SourceFiles),
		"source_hashes":          toAnySlice(spec.SourceHashes),
		"prompt_hash":            spec.PromptHash,
		"model_id":               spec.ModelID,
		"response_hash":          spec.ResponseHash,
		"wiki_files_written":     toAnySlice(spec.WikiFilesWritten),
		"wiki_file_hashes_after": toAnyStringMap(spec.WikiFileHashesAfter),
		"previous_chain_hash":    prevChainHash,
	}
	if prevID == nil {
		out["previous_id"] = nil
	} else {
		out["previous_id"] = *prevID
	}
	if spec.Metadata != nil {
		out["metadata"] = spec.Metadata
	}
	if spec.TenantID != "" {
		out["tenant_id"] = spec.TenantID
	}
	return out
}

func appendOptionalExcluded(record map[string]any, spec RecordSpec, id, chainHash string) {
	// HMAC: prefer per-key DEK if provided, else fallback single-key.
	var mac []byte
	switch {
	case spec.DEK != nil:
		h := hmac.New(sha256.New, spec.DEK)
		h.Write([]byte(id + "|" + chainHash))
		mac = h.Sum(nil)
		record["hmac"] = hex.EncodeToString(mac)
		record["key_id"] = spec.KeyID
	case spec.FallbackHMACKey != nil:
		h := hmac.New(sha256.New, spec.FallbackHMACKey)
		h.Write([]byte(id + "|" + chainHash))
		mac = h.Sum(nil)
		record["hmac"] = hex.EncodeToString(mac)
		// no key_id
	}
	if len(spec.FactHashesAdded) > 0 {
		record["fact_hashes_added"] = toAnySlice(spec.FactHashesAdded)
	}
	if len(spec.FactHashesSuperseded) > 0 {
		record["fact_hashes_superseded"] = toAnySlice(spec.FactHashesSuperseded)
	}
}

// BundleFromDEKs builds a keys.Bundle with the given DEKs encrypted
// under the given KEK. State is "active" by default; pass per-key
// overrides via the optional states map.
func BundleFromDEKs(workspaceID string, kek []byte, deks map[string][]byte, states map[string]string) *keys.Bundle {
	b := &keys.Bundle{Version: 1, WorkspaceID: workspaceID}
	now := time.Now().UTC().Format(time.RFC3339)
	keyIDs := make([]string, 0, len(deks))
	for k := range deks {
		keyIDs = append(keyIDs, k)
	}
	sort.Strings(keyIDs)
	for _, kid := range keyIDs {
		state := "active"
		if s, ok := states[kid]; ok {
			state = s
		}
		ct, nonce, tag, err := encryptDEK(deks[kid], kek)
		if err != nil {
			panic(err) // fixture path; we control inputs
		}
		b.Keys = append(b.Keys, keys.KeyRecord{
			KeyID:           kid,
			KeyState:        state,
			CreatedAt:       now,
			EncryptedDEKHex: hex.EncodeToString(ct),
			NonceHex:        hex.EncodeToString(nonce),
			AuthTagHex:      hex.EncodeToString(tag),
		})
	}
	return b
}

// encryptDEK wraps a DEK under a KEK with AES-256-GCM. Returns
// (ciphertext, nonce, auth_tag) as three separate slices matching the
// daemon's wrapDek() storage shape.
func encryptDEK(dek, kek []byte) (ciphertext, nonce, authTag []byte, err error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	sealed := gcm.Seal(nil, nonce, dek, nil)
	// AEAD.Seal in Go returns ciphertext||tag. Split for storage.
	if len(sealed) < AuthTagBytes {
		return nil, nil, nil, fmt.Errorf("sealed length %d < tag length %d", len(sealed), AuthTagBytes)
	}
	cut := len(sealed) - AuthTagBytes
	ciphertext = sealed[:cut]
	authTag = sealed[cut:]
	return ciphertext, nonce, authTag, nil
}

// AuthTagBytes mirrors keys.AuthTagBytes for use in this package.
const AuthTagBytes = 16

// RandomBytes returns n cryptographically random bytes (fatal on
// failure — only used in fixture-generation paths, never at verify time).
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// WritePack materializes a Chain into a Compliance Pack directory at
// dir. Creates manifest.json + chain.jsonl + keys.json.
func WritePack(dir string, ch *Chain) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// manifest.json
	manifest := map[string]any{
		"version":    1,
		"tenant_id":  ch.WorkspaceID,
		"summary":    "wotw-verify fixture",
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}
	mBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), mBytes, 0o644); err != nil {
		return err
	}

	// chain.jsonl — write canonical-JSON-encoded objects to match what
	// the daemon would write. The daemon uses JSON.stringify(record) for
	// its append, which does NOT canonical-sort keys; it preserves
	// insertion order. For fixtures we use canonical sort to make file
	// output deterministic across runs.
	jsonlPath := filepath.Join(dir, "chain.jsonl")
	jf, err := os.Create(jsonlPath)
	if err != nil {
		return err
	}
	defer jf.Close()
	for _, r := range ch.Records {
		b, err := canonical.Encode(r)
		if err != nil {
			return err
		}
		if _, err := jf.Write(b); err != nil {
			return err
		}
		if _, err := jf.Write([]byte("\n")); err != nil {
			return err
		}
	}

	// keys.json (optional)
	if ch.Bundle != nil {
		kBytes, err := json.MarshalIndent(ch.Bundle, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "keys.json"), kBytes, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func toAnySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func toAnyStringMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
