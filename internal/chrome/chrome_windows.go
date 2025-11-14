package chrome

// https://groups.google.com/d/msg/golang-nuts/bUetmxErnTw/GHC5obCcmTMJ
// https://play.golang.org/p/fknP9AuLU-
// https://stackoverflow.com/a/60423699

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cryptprotect_ui_forbidden = 0x1
)

var (
	dllcrypt32  = windows.NewLazySystemDLL("Crypt32.dll")
	dllkernel32 = windows.NewLazySystemDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)

type data_blob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *data_blob {
	if len(d) == 0 {
		return &data_blob{}
	}
	return &data_blob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *data_blob) toByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func decryptDPAPI(data []byte) ([]byte, error) {
	var outblob data_blob
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, cryptprotect_ui_forbidden, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.toByteArray(), nil
}

// requires the path of the "Local State" json file relative to the cookie store file
// to be the same as originally
func (s *CookieStore) getKeyringPassword(useSaved bool) ([]byte, error) {
	// this master key is used globally for all Chrome profiles

	if s == nil {
		return nil, errors.New(`cookie store is nil`)
	}
	if useSaved && s.KeyringPasswordBytes != nil {
		// Return cached password
		return s.KeyringPasswordBytes, nil
	}

	var stateFile string
	var err error
	// the "Local State" json file is normally one or two directory above the "Cookies" database
	dir := filepath.Dir(s.FileNameStr)
	if filepath.Base(dir) == `Network` { // Chrome 96
		dir = filepath.Dir(dir)
	}
	stateFile, err = filepath.Abs(filepath.Join(filepath.Dir(dir), `Local State`))
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for Local State: %w", err)
	}

	if useSaved {
		if kpw, ok := keyringPasswordMap.get(stateFile); ok {
			return kpw, nil
		}
	}

	stateBytes, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State file %s: %w", stateFile, err)
	}

	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(stateBytes, &localState); err != nil {
		return nil, fmt.Errorf("failed to parse Local State JSON: %w", err)
	}

	if localState.OSCrypt.EncryptedKey == "" {
		return nil, errors.New("encrypted_key not found in Local State")
	}

	key, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	if len(key) < 5 || !bytes.HasPrefix(key, []byte(`DPAPI`)) {
		return nil, fmt.Errorf(`not a DPAPI key (len: %d, prefix: %q)`, len(key), string(key[:min(len(key), 10)]))
	}
	key = key[5:] // strip "DPAPI"
	key, err = decryptDPAPI(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DPAPI key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf(`master key is not 32 bytes long (got %d bytes)`, len(key))
	}
	s.KeyringPasswordBytes = key
	keyringPasswordMap.set(stateFile, key)

	// Successfully retrieved and decrypted the master key
	return s.KeyringPasswordBytes, nil
}
