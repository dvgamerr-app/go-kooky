//go:build windows

package browser

import (
	"syscall"
	"unsafe"
)

var (
	dllCrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllKernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllCrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllKernel32.NewProc("LocalFree")
)

type DataBlob struct {
	cbData uint32
	pbData *byte
}

// decrypt uses Windows DPAPI to decrypt data owned by the current user.
func decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	input := DataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	var output DataBlob
	result, _, err := procDecryptData.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&output)),
	)
	if result == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(output.pbData)))

	decrypted := make([]byte, output.cbData)
	copy(decrypted, unsafe.Slice(output.pbData, output.cbData))
	return decrypted, nil
}
