//go:build !windows

package browser

import "errors"

var errDPAPIUnavailable = errors.New("DPAPI only available on Windows")

func decrypt(_ []byte) ([]byte, error) {
	return nil, errDPAPIUnavailable
}
