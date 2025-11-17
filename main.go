package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

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

// Decrypt ใช้ Windows DPAPI สำหรับ decrypt ข้อมูล
func decrypt(data []byte) ([]byte, error) {
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

// GetAESKey อ่าน encryption key จาก Local State file
func getAESKey(localStatePath string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, err
	}

	encryptedKey := localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string)
	decodedKey, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, err
	}

	// ตัด "DPAPI" prefix (5 bytes แรก)
	decodedKey = decodedKey[5:]

	// Decrypt ด้วย DPAPI
	key, err := decrypt(decodedKey)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// DecryptValue decrypt cookie value
func decryptValue(encryptedValue []byte, key []byte) (string, error) {
	if len(encryptedValue) == 0 {
		return "", nil
	}

	// ถ้าขึ้นต้นด้วย "v10" หรือ "v11" ใช้ AES-GCM
	if len(encryptedValue) > 3 && encryptedValue[0] == 'v' && encryptedValue[1] == '1' {
		if key == nil {
			return "", fmt.Errorf("AES key is required for v10/v11 encryption")
		}

		// ตัด prefix "v10" หรือ "v11" (3 bytes)
		encryptedValue = encryptedValue[3:]

		// Nonce คือ 12 bytes แรก
		nonce := encryptedValue[:12]
		ciphertext := encryptedValue[12:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}

		plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return "", err
		}

		return string(plaintext), nil
	}

	// ถ้าไม่ใช่ v10/v11 ลองใช้ DPAPI
	decrypted, err := decrypt(encryptedValue)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func main() {
	// Setup zerolog
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	})

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get home directory")
	}

	operaPath := filepath.Join(homeDir, "AppData", "Roaming", "Opera Software", "Opera Stable")
	cookiesDB := filepath.Join(operaPath, "Default", "Network", "Cookies")
	localStatePath := filepath.Join(operaPath, "Local State")

	if _, err := os.Stat(cookiesDB); os.IsNotExist(err) {
		log.Fatal().Str("path", cookiesDB).Msg("Cookies file not found")
	}

	tempDB := filepath.Join(os.TempDir(), "Cookies_temp")
	input, err := os.ReadFile(cookiesDB)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read cookies file")
	}
	err = os.WriteFile(tempDB, input, 0644)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create temp file")
	}
	defer os.Remove(tempDB)

	log.Info().Str("temp_db", tempDB).Msg("Database copied successfully")

	key, err := getAESKey(localStatePath)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read AES key, will try DPAPI fallback")
		key = nil
	} else {
		log.Info().Int("key_len", len(key)).Msg("AES key loaded successfully")
	}

	db, err := sql.Open("sqlite", tempDB)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer db.Close()

	log.Info().Msg("Database connected")

	rows, err := db.Query("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc FROM cookies")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to query cookies")
	}
	defer rows.Close()

	log.Info().Msg("Reading cookies from Opera...")
	count := 0

	for rows.Next() {
		var cookie Cookie
		var encryptedValue []byte

		err := rows.Scan(
			&cookie.Host,
			&cookie.Name,
			&encryptedValue,
			&cookie.Path,
			&cookie.ExpiresUTC,
			&cookie.IsSecure,
			&cookie.IsHttpOnly,
			&cookie.CreationUTC,
			&cookie.LastAccessUTC,
		)
		if err != nil {
			log.Error().Err(err).Msg("Failed to scan row")
			continue
		}

		// แสดง encryption version (3 bytes แรก)
		var version string
		if len(encryptedValue) >= 3 {
			version = string(encryptedValue[:3])
		} else {
			version = "unknown"
		}

		log.Debug().
			Str("cookie_name", cookie.Name).
			Str("host", cookie.Host).
			Str("version", version).
			Str("version_hex", fmt.Sprintf("%x", encryptedValue[:min(3, len(encryptedValue))])).
			Msg("Encryption version")

		decryptedValue, err := decryptValue(encryptedValue, key)
		if err != nil {
			log.Warn().
				Err(err).
				Str("cookie_name", cookie.Name).
				Str("host", cookie.Host).
				Int("encrypted_len", len(encryptedValue)).
				Msg("Failed to decrypt cookie")
			decryptedValue = "[DECRYPT FAILED]"
		} else {
			// Opera cookies มี 32-byte header ข้างหน้า (checksum/signature)
			// ให้ตัดออกถ้ามีความยาวมากกว่า 32 bytes
			if len(decryptedValue) > 32 {
				decryptedValue = decryptedValue[32:]
			}

			log.Debug().
				Str("cookie_name", cookie.Name).
				Str("host", cookie.Host).
				Int("value_len", len(decryptedValue)).
				Msg("Cookie decrypted successfully")
		}

		cookie.Value = decryptedValue

		fmt.Printf("\n========================================\n")
		fmt.Printf("Host: %s\n", cookie.Host)
		fmt.Printf("Name: %s\n", cookie.Name)
		fmt.Printf("Value: %s\n", cookie.Value)
		fmt.Printf("Path: %s\n", cookie.Path)
		fmt.Printf("Secure: %v | HttpOnly: %v\n", cookie.IsSecure, cookie.IsHttpOnly)

		count++
	}

	if err = rows.Err(); err != nil {
		log.Fatal().Err(err).Msg("Error reading rows")
	}

	log.Info().Int("total", count).Msg("Cookies read successfully")
}
