// Package canonical produces JS-compatible canonical JSON byte sequences
// for SHA-256 hashing.
//
// The wotw daemon (TypeScript) computes provenance record ids by
//
//	id = sha256(canonicalJson(payload))
//
// where canonicalJson is JavaScript's `JSON.stringify(normalize(value))`
// after recursively sorting object keys lexicographically.
//
// This package reproduces that algorithm byte-for-byte so a Go verifier
// can recompute the same id from a parsed record.
//
// JS quirks we must match:
//   - Object keys sorted lexicographically (recursive).
//   - HTML characters (<, >, &) NOT escaped — JS leaves them literal.
//     Go's encoding/json escapes them by default; we disable that.
//   - Unicode line/paragraph separators (  /  ) NOT escaped —
//     JS leaves them literal in JSON.stringify output. We do too.
//   - Non-ASCII characters NOT escaped — pass through as UTF-8 bytes.
//   - Integers serialize as their bare decimal form (1, not 1.0).
//   - null/true/false render in lowercase, no whitespace anywhere.
//
// Reference: src/provenance/hash.ts in watcher-on-the-wall (function
// canonicalJson + sha256Canonical).
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// Encode returns the canonical JSON byte sequence for v.
//
// v must be a value produced by encoding/json.Unmarshal into any (so:
// map[string]any, []any, string, bool, float64, nil, or json.Number).
// Any other Go type triggers an error.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SHA256Hex returns the SHA-256 hex digest of the canonical JSON form of v.
func SHA256Hex(v any) (string, error) {
	b, err := Encode(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// SHA256HexString returns the SHA-256 hex digest of a literal string.
//
// Used for chain_hash = sha256(previous_chain_hash + id) — a hash of the
// concatenation of two hex strings, not of canonical JSON.
func SHA256HexString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func write(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return writeString(buf, x)
	case json.Number:
		// json.Number preserves the original textual representation
		// from the input — exactly what JS would emit.
		buf.WriteString(string(x))
		return nil
	case float64:
		return writeFloat(buf, x)
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
		return nil
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case []string:
		buf.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, s); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		return writeObject(buf, x)
	case map[string]string:
		obj := make(map[string]any, len(x))
		for k, vv := range x {
			obj[k] = vv
		}
		return writeObject(buf, obj)
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
}

func writeObject(buf *bytes.Buffer, obj map[string]any) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := write(buf, obj[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// writeString matches JavaScript's JSON.stringify string serialization:
//   - wrap in double quotes
//   - backslash-escape: \", \\, \b, \f, \n, \r, \t
//   - \u00XX escape control characters U+0000..U+001F that don't have a
//     named escape
//   - leave everything else (including <, >, &,  ,  , and all
//     non-ASCII multibyte UTF-8) untouched
func writeString(buf *bytes.Buffer, s string) error {
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch b {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if b < 0x20 {
				// other C0 control char
				fmt.Fprintf(buf, `\u%04x`, b)
			} else {
				buf.WriteByte(b)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// writeFloat matches JS's number serialization for our finite, non-integer
// case. The daemon's ProvenanceRecord only ever stores integers in
// numeric fields (seq, fact counts, byte sizes); we still cover the
// general float case because canonical JSON is a general utility.
//
// Integers serialize without a trailing ".0" (JS: 1, not 1.0).
// Non-integer floats use Go's default %g-equivalent, which matches JS
// for normal magnitudes. Infinity/NaN are not valid JSON — error out.
func writeFloat(buf *bytes.Buffer, f float64) error {
	if f != f || f > 1e308 || f < -1e308 {
		return fmt.Errorf("canonical: %v cannot be encoded as JSON", f)
	}
	// If f is an integer in float form, emit as integer.
	if f == float64(int64(f)) && f > -1e15 && f < 1e15 {
		buf.WriteString(strconv.FormatInt(int64(f), 10))
		return nil
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}
