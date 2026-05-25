package verify_test

import (
	"encoding/hex"
	"os"
)

func writeHex(path string, data []byte) error {
	return os.WriteFile(path, []byte(hex.EncodeToString(data)+"\n"), 0o600)
}
