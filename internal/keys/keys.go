// Package keys parses workspace key material from a Compliance Pack
// and resolves DEKs (data encryption keys) for HMAC verification.
//
// Pack layout (v1, as defined for wotw-verify v0.1.0):
//
//	<pack>/keys.json   (or inside <pack>.zip)
//
// keys.json shape:
//
//	{
//	  "version": 1,
//	  "workspace_id": "<tenant_id>",
//	  "keys": [
//	    {
//	      "key_id": "<uuid>",
//	      "key_state": "active" | "rotating" | "archived" | "revoked",
//	      "created_at": "<iso8601>",
//	      "rotated_at": null | "<iso8601>",
//	      "revoked_at": null | "<iso8601>",
//	      "encrypted_dek_hex": "<hex>",
//	      "nonce_hex":         "<hex>",
//	      "auth_tag_hex":      "<hex>"
//	    },
//	    ...
//	  ]
//	}
//
// The encrypted_dek/nonce/auth_tag triple is AES-256-GCM ciphertext
// under the workspace KEK. The verifier MUST be supplied a KEK
// (--workspace-key) to decrypt before HMAC verification.
//
// This is intentionally a different format from the daemon's on-disk
// .wotw/keys.db SQLite table — the daemon-side store is rotation-aware
// and process-bound; the export is a static snapshot. CT4.01 (cloud
// Compliance Pack export, separate goal) will produce this shape from
// the daemon's keys.db.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// KEKBytes is the required length of a workspace KEK.
const KEKBytes = 32

// DEKBytes is the length of a workspace DEK after unwrapping.
const DEKBytes = 32

// NonceBytes is the AES-GCM IV length used by the daemon.
const NonceBytes = 12

// AuthTagBytes is the AES-GCM authentication tag length.
const AuthTagBytes = 16

// Bundle is the parsed keys.json document.
type Bundle struct {
	Version     int         `json:"version"`
	WorkspaceID string      `json:"workspace_id"`
	Keys        []KeyRecord `json:"keys"`
}

// KeyRecord describes one workspace DEK in encrypted form.
type KeyRecord struct {
	KeyID           string  `json:"key_id"`
	KeyState        string  `json:"key_state"`
	CreatedAt       string  `json:"created_at"`
	RotatedAt       *string `json:"rotated_at,omitempty"`
	RevokedAt       *string `json:"revoked_at,omitempty"`
	EncryptedDEKHex string  `json:"encrypted_dek_hex"`
	NonceHex        string  `json:"nonce_hex"`
	AuthTagHex      string  `json:"auth_tag_hex"`
}

// LoadBundle reads + parses keys.json from a path on disk.
func LoadBundle(path string) (*Bundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keys.json: %w", err)
	}
	return ParseBundle(b)
}

// ParseBundle decodes a keys.json byte sequence.
func ParseBundle(b []byte) (*Bundle, error) {
	var bundle Bundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		return nil, fmt.Errorf("parse keys.json: %w", err)
	}
	if bundle.Version != 1 {
		return nil, fmt.Errorf("unsupported keys.json version %d (this verifier supports version 1)", bundle.Version)
	}
	if bundle.WorkspaceID == "" {
		return nil, errors.New("keys.json: workspace_id is empty")
	}
	for i, k := range bundle.Keys {
		if k.KeyID == "" {
			return nil, fmt.Errorf("keys[%d]: key_id is empty", i)
		}
		switch k.KeyState {
		case "active", "rotating", "archived", "revoked":
		default:
			return nil, fmt.Errorf("keys[%d]: invalid key_state %q", i, k.KeyState)
		}
	}
	return &bundle, nil
}

// ParseKEK decodes a 32-byte KEK from either base64 (preferred) or
// hex encoding. Whitespace and surrounding newlines are trimmed.
// Mirrors the daemon's parseKek() in src/keys/envelope.ts.
func ParseKEK(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, errors.New("workspace KEK is empty")
	}
	// Try base64 first.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == KEKBytes {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil && len(b) == KEKBytes {
		return b, nil
	}
	// Try hex.
	if b, err := hex.DecodeString(s); err == nil {
		if len(b) != KEKBytes {
			return nil, fmt.Errorf("hex-decoded KEK is %d bytes, want %d", len(b), KEKBytes)
		}
		return b, nil
	}
	return nil, errors.New("workspace KEK is neither valid base64 (32 bytes) nor valid hex (64 chars)")
}

// LoadKEKFromFile reads a KEK file and parses its contents.
func LoadKEKFromFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read KEK file: %w", err)
	}
	kek, err := ParseKEK(b)
	if err != nil {
		return nil, fmt.Errorf("parse KEK file %s: %w", path, err)
	}
	return kek, nil
}

// Resolver implements provenance.HMACKeyResolver against a parsed
// Bundle decrypted under a KEK. Cached DEKs are held in memory for
// the lifetime of the resolver; the bundle is decrypted lazily on
// first lookup per key_id.
type Resolver struct {
	bundle *Bundle
	kek    []byte
	cache  map[string][]byte // key_id → plaintext DEK
	states map[string]string // key_id → key_state
}

// NewResolver constructs a Resolver. Pass a nil bundle to construct a
// no-op resolver that will return (nil, "", nil) for every lookup.
func NewResolver(bundle *Bundle, kek []byte) *Resolver {
	if bundle == nil {
		return &Resolver{}
	}
	states := make(map[string]string, len(bundle.Keys))
	for _, k := range bundle.Keys {
		states[k.KeyID] = k.KeyState
	}
	return &Resolver{
		bundle: bundle,
		kek:    kek,
		cache:  make(map[string][]byte, len(bundle.Keys)),
		states: states,
	}
}

// ResolveByID decrypts and returns the DEK for the given key_id.
//
// Returns (nil, "", nil) if the bundle doesn't contain that key — the
// caller treats this as a verification failure for the record but the
// resolver itself doesn't error.
//
// Returns (nil, "", err) if decryption fails (KEK is wrong OR
// ciphertext is corrupt).
func (r *Resolver) ResolveByID(keyID string) ([]byte, string, error) {
	if r.bundle == nil {
		return nil, "", nil
	}
	if dek, ok := r.cache[keyID]; ok {
		return dek, r.states[keyID], nil
	}
	for _, k := range r.bundle.Keys {
		if k.KeyID != keyID {
			continue
		}
		dek, err := r.unwrap(k)
		if err != nil {
			return nil, k.KeyState, err
		}
		r.cache[keyID] = dek
		return dek, k.KeyState, nil
	}
	return nil, "", nil
}

// Fallback returns (nil, nil) — the bundle-backed resolver doesn't
// provide a 4-tier fallback. Records lacking key_id but carrying hmac
// are flagged as pre-G5 attestation; the verifier reports them as
// unattested (or fails them under --strict).
func (r *Resolver) Fallback() ([]byte, error) { return nil, nil }

// unwrap decrypts a single KeyRecord's DEK under the resolver's KEK.
func (r *Resolver) unwrap(k KeyRecord) ([]byte, error) {
	if r.kek == nil {
		return nil, errors.New("no KEK provided; cannot decrypt workspace DEK")
	}
	ct, err := hex.DecodeString(k.EncryptedDEKHex)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted_dek_hex: %w", err)
	}
	nonce, err := hex.DecodeString(k.NonceHex)
	if err != nil {
		return nil, fmt.Errorf("decode nonce_hex: %w", err)
	}
	if len(nonce) != NonceBytes {
		return nil, fmt.Errorf("nonce is %d bytes, want %d", len(nonce), NonceBytes)
	}
	tag, err := hex.DecodeString(k.AuthTagHex)
	if err != nil {
		return nil, fmt.Errorf("decode auth_tag_hex: %w", err)
	}
	if len(tag) != AuthTagBytes {
		return nil, fmt.Errorf("auth_tag is %d bytes, want %d", len(tag), AuthTagBytes)
	}

	block, err := aes.NewCipher(r.kek)
	if err != nil {
		return nil, fmt.Errorf("aes new: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm new: %w", err)
	}

	// Go's AES-GCM expects ciphertext||tag as a single byte slice.
	// The daemon stores them separately (matching Node's split into
	// {ciphertext, auth_tag}), so we concat here.
	sealed := append(ct, tag...)
	dek, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt failed (wrong KEK, or DEK tampered): %w", err)
	}
	if len(dek) != DEKBytes {
		return nil, fmt.Errorf("decrypted DEK is %d bytes, want %d", len(dek), DEKBytes)
	}
	return dek, nil
}
