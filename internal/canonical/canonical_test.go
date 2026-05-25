package canonical

import (
	"encoding/json"
	"strings"
	"testing"
)

// All expected outputs in this file were computed against JavaScript's
// JSON.stringify(normalize(value)) — the algorithm the wotw daemon uses
// (src/provenance/hash.ts canonicalJson). See internal/fixturegen for
// the cross-runtime golden generator.

func mustEncode(t *testing.T, v any) string {
	t.Helper()
	b, err := Encode(v)
	if err != nil {
		t.Fatalf("Encode(%v): %v", v, err)
	}
	return string(b)
}

func TestEncodePrimitives(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "null"},
		{true, "true"},
		{false, "false"},
		{"", `""`},
		{"hello", `"hello"`},
		{float64(0), "0"},
		{float64(1), "1"},
		{float64(-1), "-1"},
		{float64(42), "42"},
		{float64(1.5), "1.5"},
	}
	for _, c := range cases {
		got := mustEncode(t, c.in)
		if got != c.want {
			t.Errorf("Encode(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEncodeStringEscapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"quote", `a"b`, `"a\"b"`},
		{"backslash", `a\b`, `"a\\b"`},
		{"newline", "a\nb", `"a\nb"`},
		{"carriage_return", "a\rb", `"a\rb"`},
		{"tab", "a\tb", `"a\tb"`},
		{"backspace", "a\bb", `"a\bb"`},
		{"formfeed", "a\fb", `"a\fb"`},
		{"nul_byte", "a\x00b", "\"a\\u0000b\""},
		{"ctrl_a", "a\x01b", "\"a\\u0001b\""},
		{"ctrl_unit_separator", "a\x1fb", "\"a\\u001fb\""},
		// HTML chars MUST pass through literal — JS does NOT escape them
		// by default. Go's encoding/json escapes them unless explicitly
		// disabled; we never use encoding/json for the canonical path.
		{"angle_left", "<script>", `"<script>"`},
		{"ampersand", "a&b", `"a&b"`},
		// Non-ASCII multibyte UTF-8 passes through verbatim.
		{"latin", "café", `"café"`},
		{"cjk", "日本語", `"日本語"`},
		// U+2028 LINE SEPARATOR + U+2029 PARAGRAPH SEPARATOR — JS's
		// JSON.stringify leaves them literal (despite the fact they
		// terminate JS source lines). Our verifier must match.
		{"line_separator", "x y", "\"x y\""},
		{"para_separator", "x y", "\"x y\""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mustEncode(t, c.in)
			if got != c.want {
				t.Errorf("Encode(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestEncodeObjectKeySorting(t *testing.T) {
	in := map[string]any{
		"banana": float64(2),
		"apple":  float64(1),
		"cherry": float64(3),
	}
	got := mustEncode(t, in)
	want := `{"apple":1,"banana":2,"cherry":3}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncodeNestedObjectSorting(t *testing.T) {
	in := map[string]any{
		"z": map[string]any{
			"y": float64(2),
			"x": float64(1),
		},
		"a": []any{
			map[string]any{
				"q": float64(1),
				"p": float64(0),
			},
		},
	}
	got := mustEncode(t, in)
	want := `{"a":[{"p":0,"q":1}],"z":{"x":1,"y":2}}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncodeEmptyContainers(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{map[string]any{}, `{}`},
		{[]any{}, `[]`},
		{[]any{nil}, `[null]`},
		{map[string]any{"k": map[string]any{}}, `{"k":{}}`},
		{map[string]any{"k": []any{}}, `{"k":[]}`},
	}
	for _, c := range cases {
		got := mustEncode(t, c.in)
		if got != c.want {
			t.Errorf("Encode(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEncodeIntegerLikeFloatsBare(t *testing.T) {
	got := mustEncode(t, float64(1))
	if got != "1" {
		t.Errorf("float64(1) = %q, want %q", got, "1")
	}
	got = mustEncode(t, float64(1e3))
	if got != "1000" {
		t.Errorf("float64(1e3) = %q, want %q", got, "1000")
	}
}

func TestEncodeJSONNumberPreserved(t *testing.T) {
	got := mustEncode(t, json.Number("123"))
	if got != "123" {
		t.Errorf("got %q, want 123", got)
	}
}

func TestEncodeUnsupportedTypeErrors(t *testing.T) {
	type myStruct struct{ N int }
	_, err := Encode(myStruct{N: 1})
	if err == nil {
		t.Fatal("expected error on unsupported type")
	}
	if !strings.Contains(err.Error(), "unsupported type") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestProvenanceRecordCanonicalShape encodes the canonical payload form
// of a real ProvenanceRecord. The expected output is what the daemon's
// canonicalJson would produce for the same value. If this assertion
// ever breaks, either the daemon's canonical payload shape changed
// (chain compat regressed) OR our canonical encoder drifted from JS
// semantics. Both are stop-the-line bugs.
func TestProvenanceRecordCanonicalShape(t *testing.T) {
	payload := map[string]any{
		"seq":                    float64(1),
		"timestamp":              "2026-05-25T00:00:00.000Z",
		"type":                   "ingest",
		"source_files":           []any{"raw/a.md"},
		"source_hashes":          []any{"deadbeef"},
		"prompt_hash":            "p-hash",
		"model_id":               "claude-haiku-4-5",
		"response_hash":          "r-hash",
		"wiki_files_written":     []any{"wiki/x.md"},
		"wiki_file_hashes_after": map[string]any{"wiki/x.md": "w-hash"},
		"previous_id":            nil,
		"previous_chain_hash":    strings.Repeat("0", 64),
	}
	got, err := Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"model_id":"claude-haiku-4-5","previous_chain_hash":"0000000000000000000000000000000000000000000000000000000000000000","previous_id":null,"prompt_hash":"p-hash","response_hash":"r-hash","seq":1,"source_files":["raw/a.md"],"source_hashes":["deadbeef"],"timestamp":"2026-05-25T00:00:00.000Z","type":"ingest","wiki_file_hashes_after":{"wiki/x.md":"w-hash"},"wiki_files_written":["wiki/x.md"]}`
	if string(got) != want {
		t.Errorf("\n got: %s\nwant: %s", got, want)
	}
}

func TestSHA256HexString(t *testing.T) {
	// Reference: echo -n "abc" | sha256sum
	got := SHA256HexString("abc")
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestByteIdentityWithDaemonRuntime asserts that the canonical hash of
// a real ProvenanceRecord payload matches what the daemon's Node runtime
// produces from the same input. Reference values produced by running
// the daemon's canonicalJson against the live algorithm (a copy of
// src/provenance/hash.ts in watcher-on-the-wall at v0.8.3).
//
// If this assertion ever breaks, EITHER the daemon's canonicalJson has
// changed (breaking chain compat across the ecosystem) OR our Go
// reimplementation has drifted. Both are stop-the-line bugs.
func TestByteIdentityWithDaemonRuntime(t *testing.T) {
	payload := map[string]any{
		"seq":                    float64(1),
		"timestamp":              "2026-05-25T00:00:00.000Z",
		"type":                   "ingest",
		"source_files":           []any{"raw/a.md"},
		"source_hashes":          []any{"deadbeef"},
		"prompt_hash":            "p-hash",
		"model_id":               "claude-haiku-4-5",
		"response_hash":          "r-hash",
		"wiki_files_written":     []any{"wiki/x.md"},
		"wiki_file_hashes_after": map[string]any{"wiki/x.md": "w-hash"},
		"previous_id":            nil,
		"previous_chain_hash":    strings.Repeat("0", 64),
	}

	gotID, err := SHA256Hex(payload)
	if err != nil {
		t.Fatal(err)
	}
	wantID := "bd2b22d1d887bab937fc14079c23f573ef2048b6755666dee1d906ccd9c90d82"
	if gotID != wantID {
		t.Errorf("id: got %q, want %q (daemon-Node reference)", gotID, wantID)
	}

	gotChainHash := SHA256HexString(strings.Repeat("0", 64) + gotID)
	wantChainHash := "e85531c85766a8f4f0feb32d9bdd0c3b24479cd6e1f2206febb36d5c3d8fee1d"
	if gotChainHash != wantChainHash {
		t.Errorf("chain_hash: got %q, want %q (daemon-Node reference)", gotChainHash, wantChainHash)
	}
}
