package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

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
	nonce, err := GetNonce(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

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

func GetNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)

	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}
