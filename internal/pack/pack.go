// Package pack reads a wotw Compliance Pack from either a directory or
// a .zip archive.
//
// Pack layout (v1):
//
//	<pack>/
//	  manifest.json       (required) — version, tenant_id, summary
//	  chain.jsonl         (required) — the provenance chain
//	  keys.json           (optional) — workspace key bundle (encrypted DEKs)
//	  content/            (optional) — wiki files referenced by the chain
//
// The verifier reads chain.jsonl + keys.json. content/ is read only
// when the verifier is asked to validate content integrity (future
// flag; v0.1.0 doesn't implement content-hash recompute against
// wiki_file_hashes_after).
package pack

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Manifest is the parsed pack manifest.
type Manifest struct {
	Version  int    `json:"version"`
	TenantID string `json:"tenant_id"`
	// Summary is an optional human-readable description of the export.
	Summary string `json:"summary,omitempty"`
	// CreatedAt is the ISO-8601 timestamp when the pack was produced.
	CreatedAt string `json:"created_at,omitempty"`
}

// Pack is an opened Compliance Pack (file-backed or zip-backed).
type Pack struct {
	Path       string
	IsZip      bool
	Manifest   Manifest
	HasChain   bool
	HasKeys    bool
	HasContent bool

	// Internal pointers for lazy reads.
	zr *zip.ReadCloser
	// Track files inside the zip / directory for chain.jsonl + keys.json
	chainEntry string
	keysEntry  string
}

// Open inspects a pack at the given path. The path may be a directory
// or a .zip file. Returns an error if neither.
func Open(path string) (*Pack, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return openDir(path)
	}
	return openZip(path)
}

// Close releases the underlying zip handle, if any.
func (p *Pack) Close() error {
	if p.zr != nil {
		return p.zr.Close()
	}
	return nil
}

// ChainJSONL returns the chain.jsonl bytes.
func (p *Pack) ChainJSONL() (io.ReadCloser, error) {
	if !p.HasChain {
		return nil, errors.New("pack has no chain.jsonl")
	}
	if p.IsZip {
		return p.zipFile(p.chainEntry)
	}
	return os.Open(filepath.Join(p.Path, p.chainEntry))
}

// KeysJSON returns the keys.json bytes, or (nil, nil) if absent.
func (p *Pack) KeysJSON() (io.ReadCloser, error) {
	if !p.HasKeys {
		return nil, nil
	}
	if p.IsZip {
		return p.zipFile(p.keysEntry)
	}
	return os.Open(filepath.Join(p.Path, p.keysEntry))
}

func openDir(path string) (*Pack, error) {
	p := &Pack{Path: path}
	// manifest.json
	mPath := filepath.Join(path, "manifest.json")
	mBytes, err := os.ReadFile(mPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest.json: %w", err)
	}
	if err := json.Unmarshal(mBytes, &p.Manifest); err != nil {
		return nil, fmt.Errorf("parse manifest.json: %w", err)
	}
	if p.Manifest.Version != 1 {
		return nil, fmt.Errorf("unsupported pack version %d (this verifier supports version 1)", p.Manifest.Version)
	}

	// chain.jsonl
	if fileExists(filepath.Join(path, "chain.jsonl")) {
		p.HasChain = true
		p.chainEntry = "chain.jsonl"
	}
	// keys.json
	if fileExists(filepath.Join(path, "keys.json")) {
		p.HasKeys = true
		p.keysEntry = "keys.json"
	}
	// content/
	if info, err := os.Stat(filepath.Join(path, "content")); err == nil && info.IsDir() {
		p.HasContent = true
	}
	if !p.HasChain {
		return nil, errors.New("pack is missing chain.jsonl")
	}
	return p, nil
}

func openZip(path string) (*Pack, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open zip %s: %w", path, err)
	}

	p := &Pack{Path: path, IsZip: true, zr: zr}

	// First pass: locate the manifest.json. Allow it to be either at the
	// archive root OR under a single-directory prefix (a common zip
	// packaging pattern). Track the prefix so other files resolve
	// against it.
	var prefix string
	var manifestEntry string
	for _, f := range zr.File {
		name := f.Name
		if strings.HasSuffix(name, "/manifest.json") || name == "manifest.json" {
			manifestEntry = name
			prefix = strings.TrimSuffix(name, "manifest.json")
			break
		}
	}
	if manifestEntry == "" {
		zr.Close()
		return nil, errors.New("zip pack has no manifest.json")
	}

	// Parse the manifest.
	mr, err := zr.Open(manifestEntry)
	if err != nil {
		zr.Close()
		return nil, fmt.Errorf("open manifest in zip: %w", err)
	}
	mBytes, err := io.ReadAll(mr)
	mr.Close()
	if err != nil {
		zr.Close()
		return nil, fmt.Errorf("read manifest in zip: %w", err)
	}
	if err := json.Unmarshal(mBytes, &p.Manifest); err != nil {
		zr.Close()
		return nil, fmt.Errorf("parse manifest.json: %w", err)
	}
	if p.Manifest.Version != 1 {
		zr.Close()
		return nil, fmt.Errorf("unsupported pack version %d (this verifier supports version 1)", p.Manifest.Version)
	}

	// Resolve other entries.
	for _, f := range zr.File {
		name := f.Name
		switch {
		case name == prefix+"chain.jsonl":
			p.HasChain = true
			p.chainEntry = name
		case name == prefix+"keys.json":
			p.HasKeys = true
			p.keysEntry = name
		case strings.HasPrefix(name, prefix+"content/"):
			p.HasContent = true
		}
	}

	if !p.HasChain {
		zr.Close()
		return nil, errors.New("zip pack is missing chain.jsonl")
	}
	return p, nil
}

func (p *Pack) zipFile(name string) (io.ReadCloser, error) {
	if p.zr == nil {
		return nil, errors.New("zip handle is nil")
	}
	rc, err := p.zr.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open %s in zip: %w", name, err)
	}
	return rc, nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
