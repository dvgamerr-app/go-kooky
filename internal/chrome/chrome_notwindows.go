//go:build !windows
// +build !windows

package chrome

import (
	"errors"
)

func decryptDPAPI(data []byte) ([]byte, error) {
	return nil, errors.New("DPAPI decryption is only supported on Windows")
}
