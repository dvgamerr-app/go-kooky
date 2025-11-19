package browser

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/rs/zerolog"
)

var TEMP_DIR string

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	TEMP_DIR = filepath.Join(os.TempDir(), ".kooky")
	if err := os.MkdirAll(TEMP_DIR, 0755); err != nil {
		panic(err)
	}
}

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)

type DataBlob struct {
	cbData uint32
	pbData *byte
}

type Cookie struct {
	Host          string
	Name          string
	Value         string
	Path          string
	ExpiresUTC    int64
	IsSecure      bool
	IsHttpOnly    bool
	CreationUTC   int64
	LastAccessUTC int64
}

// decrypt ใช้ Windows DPAPI สำหรับ decrypt ข้อมูล
func decrypt(data []byte) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("DPAPI only available on Windows")
	}
	var outblob DataBlob
	r, _, err := procDecryptData.Call(
		uintptr(unsafe.Pointer(&DataBlob{uint32(len(data)), &data[0]})),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&outblob)),
	)
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))

	return unsafe.Slice(outblob.pbData, outblob.cbData), nil
}

// getAESKey อ่าน encryption key จาก Local State file
func getAESKey(localStatePath string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var localState map[string]any
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, err
	}

	encryptedKey := localState["os_crypt"].(map[string]any)["encrypted_key"].(string)
	decodedKey, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, err
	}

	// ตัด "DPAPI" prefix (5 bytes แรก)
	decodedKey = decodedKey[5:]

	if runtime.GOOS == "windows" {
		// Decrypt ด้วย DPAPI
		key, err := decrypt(decodedKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	} else {
		// สำหรับ OS อื่น assume ไม่ encrypt อีก (ไม่ถูกต้อง แต่สำหรับ demo)
		return decodedKey, nil
	}
}

// decryptValue decrypt cookie value
func decryptValue(encryptedValue []byte, key []byte) (string, error) {
	if len(encryptedValue) == 0 {
		return "", nil
	}

	// Try AES if key is available and looks like v10/v11
	if key != nil && len(encryptedValue) > 3 && encryptedValue[0] == 'v' && encryptedValue[1] == '1' {
		// ตัด prefix "v10" หรือ "v11" (3 bytes)
		encryptedValueTrim := encryptedValue[3:]

		// Nonce คือ 12 bytes แรก
		nonce := encryptedValueTrim[:12]
		ciphertext := encryptedValueTrim[12:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
		if err == nil {
			return string(plaintext), nil
		}
		// If AES fails, fall back to DPAPI
	}

	// Try DPAPI
	if runtime.GOOS == "windows" {
		decrypted, err := decrypt(encryptedValue)
		if err != nil {
			return "", err
		}
		return string(decrypted), nil
	}

	// สำหรับ OS อื่น assume plaintext หรืออะไร แต่จริงๆ ไม่
	return string(encryptedValue), nil
}
