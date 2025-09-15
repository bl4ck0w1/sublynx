package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(bytes), nil
}

func CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[int(b)%len(letters)]
	}
	return string(bytes), nil
}

func SHA256Hash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func SHA256HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func SHA256HashFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func EncryptAES(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptAES(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return pt, nil
}

func GenerateAESKey(size int) ([]byte, error) {
	switch size {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("invalid key size: must be 16, 24, or 32 bytes")
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

func GenerateAESKeyFromPassword(password string, size int) ([]byte, error) {
	switch size {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("invalid key size: must be 16, 24, or 32 bytes")
	}
	sum := sha256.Sum256([]byte(password))
	return sum[:size], nil
}

func HMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func VerifyHMAC(key, data, expectedMAC []byte) bool {
	actual := HMAC(key, data)
	return subtle.ConstantTimeCompare(actual, expectedMAC) == 1
}

func DeriveKey(password string, salt []byte, iterations, keyLength int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha256.New)
}

func GenerateIV(size int) ([]byte, error) {
	iv := make([]byte, size)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}
	return iv, nil
}

func PadPKCS7(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func UnpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if data[i] != byte(pad) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-pad], nil
}

func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func GenerateAPIToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate API token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func GenerateJWTSecret() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}


func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func ValidateJWT(token, secret string) (bool, error) {
	if token == "" || secret == "" {
		return false, errors.New("token/secret must not be empty")
	}

	keyFn := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}

	parsed, err := jwt.Parse(token, keyFn,
		jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}),
		jwt.WithLeeway(30*time.Second),
		jwt.WithAudience(nil),
	)
	if err != nil {
		return false, err
	}
	return parsed.Valid, nil
}

func GenerateKeyPair(bits int) (interface{}, interface{}, error) {
	if bits < 2048 {
		return nil, nil, fmt.Errorf("rsa key size too small: %d", bits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate rsa key: %w", err)
	}
	return &priv.PublicKey, priv, nil
}


func SignData(data []byte, privateKey interface{}) ([]byte, error) {
	priv, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("privateKey must be *rsa.PrivateKey")
	}
	h := sha256.Sum256(data)
	sig, err := rsa.SignPSS(rand.Reader, priv, sha256.New(), h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return sig, nil
}

func VerifySignature(data, signature []byte, publicKey interface{}) (bool, error) {
	pub, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("publicKey must be *rsa.PublicKey")
	}
	h := sha256.Sum256(data)
	if err := rsa.VerifyPSS(pub, sha256.New(), h[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
		return false, nil
	}
	return true, nil
}

func MaskSensitiveData(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}

func RedactSecrets(v interface{}) interface{} {
	suspicious := map[string]struct{}{
		"password": {}, "pass": {}, "pwd": {}, "secret": {}, "token": {}, "access_token": {},
		"refresh_token": {}, "apikey": {}, "api_key": {}, "authorization": {}, "auth": {},
		"cookie": {}, "jwt": {}, "private_key": {}, "client_secret": {},
	}
	return redactRecursive(v, suspicious)
}

func redactRecursive(v interface{}, keys map[string]struct{}) interface{} {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)

	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return v
		}
		out := make(map[string]interface{}, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			k := iter.Key().String()
			lk := strings.ToLower(k)
			if _, found := keys[lk]; found {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = redactRecursive(iter.Value().Interface(), keys)
		}
		return out

	case reflect.Struct:
		out := make(map[string]interface{}, rv.NumField())
		rt := rv.Type()
		for i := 0; i < rv.NumField(); i++ {
			f := rt.Field(i)
			// export only
			if f.PkgPath != "" {
				continue
			}
			name := f.Name
			jsonTag := f.Tag.Get("json")
			if jsonTag != "" && jsonTag != "-" {
				name = strings.Split(jsonTag, ",")[0]
				if name == "" {
					name = f.Name
				}
			}
			lk := strings.ToLower(name)
			if _, found := keys[lk]; found {
				out[name] = "[REDACTED]"
				continue
			}
			out[name] = redactRecursive(rv.Field(i).Interface(), keys)
		}
		return out

	case reflect.Slice, reflect.Array:
		n := rv.Len()
		out := make([]interface{}, n)
		for i := 0; i < n; i++ {
			out[i] = redactRecursive(rv.Index(i).Interface(), keys)
		}
		return out

	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return redactRecursive(rv.Elem().Interface(), keys)

	default:
		return v
	}
}
