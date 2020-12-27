package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultIterationCount = 100
	keyLength             = 32
)

var hashFunc = sha256.New

func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, defaultIterationCount, keyLength, hashFunc)
}

// Encrypt performs AES-256 GCM encryption with a given 32-bytes key.
func Encrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return encryptedData, nil
}

// Decrypt performs AES-256 GCM decryption with a given 32-bytes key.
func Decrypt(key, encryptedData []byte) ([]byte, error) {
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

// EncryptWithRSA encrypts the given data with RSA-OAEP.
// pubKey must be a RSA public key in PEM format.
func EncryptWithRSA(pubKey, data []byte) ([]byte, error) {
	pem, _ := pem.Decode(pubKey)
	if pem == nil {
		return nil, fmt.Errorf("given public key is not in pem format")
	}

	var (
		parsedPublicKey *rsa.PublicKey
		err             error
	)
	// At first try to parse public key according to PKCS #1.
	parsedPublicKey, err = x509.ParsePKCS1PublicKey(pem.Bytes)
	if err != nil {
		key, err := x509.ParsePKIXPublicKey(pem.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		var ok bool
		parsedPublicKey, ok = key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("given public key is not an RSA key")
		}
	}

	return rsa.EncryptOAEP(hashFunc(), rand.Reader, parsedPublicKey, data, nil)
}

// DecryptWithRSA decrypts the given encrypted data with RSA-OAEP.
// privKey must be a RSA private key in PEM format.
func DecryptWithRSA(privKey, encrypted []byte) ([]byte, error) {
	pem, _ := pem.Decode(privKey)
	if pem == nil {
		return nil, fmt.Errorf("given private key is not in pem format")
	}

	var (
		parsedPrivateKey *rsa.PrivateKey
		err              error
	)
	// At first try to parse private key according to PKCS #1.
	parsedPrivateKey, err = x509.ParsePKCS1PrivateKey(pem.Bytes)
	if err != nil {
		key, err := x509.ParsePKCS8PrivateKey(pem.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		parsedPrivateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("given private key is not an RSA key")
		}
	}

	return rsa.DecryptOAEP(hashFunc(), rand.Reader, parsedPrivateKey, encrypted, nil)
}
