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
func Encrypt(key, plaintext []byte) ([]byte, error) {
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

	encrypted := gcm.Seal(nonce, nonce, plaintext, nil)
	return encrypted, nil
}

// Decrypt performs AES-256 GCM decryption with a given 32-bytes key.
func Decrypt(key, encrypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("invalid cipher test")
	}
	nonce := encrypted[:nonceSize]
	encryptedText := encrypted[nonceSize:]

	return gcm.Open(nil, nonce, encryptedText, nil)
}

// EncryptWithRSA encrypts the given data with RSA-OAEP.
// pubKey must be a RSA public key in PEM or DER format.
func EncryptWithRSA(pubKey, plaintext []byte) ([]byte, error) {
	// At first it assumes the pubKey is in DER format.
	derKey, err := parsePubKeyInDER(pubKey)
	if err == nil {
		return rsa.EncryptOAEP(hashFunc(), rand.Reader, derKey, plaintext, nil)
	}

	// Second, assumes it is in PEM format.
	pem, _ := pem.Decode(pubKey)
	if pem == nil {
		return nil, fmt.Errorf("given public key format is neither DER nor PEM")
	}
	pemKey, err := parsePubKeyInDER(pem.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(hashFunc(), rand.Reader, pemKey, plaintext, nil)
}

func parsePubKeyInDER(der []byte) (*rsa.PublicKey, error) {
	// At first try to parse public key according to PKCS #1.
	pkcs1Key, err := x509.ParsePKCS1PublicKey(der)
	if err == nil {
		return pkcs1Key, nil
	}

	// Then parse it according to PKIX.
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	pkixKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("given public key is not an RSA key")
	}
	return pkixKey, nil
}

// DecryptWithRSA decrypts the given encrypted data with RSA-OAEP.
// privKey must be a RSA private key in PEM or DER format.
func DecryptWithRSA(privKey, encrypted []byte) ([]byte, error) {
	// At first it assumes the privKey is in DER format.
	derKey, err := parsePrivKeyInDER(privKey)
	if err == nil {
		return rsa.DecryptOAEP(hashFunc(), rand.Reader, derKey, encrypted, nil)
	}

	// Second, assumes it is in PEM format.
	pem, _ := pem.Decode(privKey)
	if pem == nil {
		return nil, fmt.Errorf("given private key format is neither DER nor PEM")
	}
	pemKey, err := parsePrivKeyInDER(pem.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(hashFunc(), rand.Reader, pemKey, encrypted, nil)
}

func parsePrivKeyInDER(der []byte) (*rsa.PrivateKey, error) {
	// At first try to parse private key according to PKCS #1.
	pkcs1Key, err := x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		return pkcs1Key, nil
	}

	// Then parse it according to PKCS #8.
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	pkcs8Key, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("given private key is not an RSA key")
	}
	return pkcs8Key, nil
}
