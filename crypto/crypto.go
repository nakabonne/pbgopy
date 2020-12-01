package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultIterationCount = 100
	keyLength             = 32
)

func Encrypt(password string, salt, data []byte) ([]byte, error) {
	key := pbkdf2.Key([]byte(password), salt, defaultIterationCount, keyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	// TODO: Stop using an empty nonce for GCM
	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return encryptedData, nil
}

func Decrypt(password string, salt, encryptedData []byte) ([]byte, error) {
	key := pbkdf2.Key([]byte(password), salt, defaultIterationCount, keyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("invalid cipher test")
	}
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

// RandomBytes yields a random bytes with the given length.
func RandomBytes(length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return b
}
