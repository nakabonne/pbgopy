package commands

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	pbcrypto "github.com/nakabonne/pbgopy/crypto"
	"github.com/nakabonne/pbgopy/datasize"
)

const (
	pbgopyServerEnv           = "PBGOPY_SERVER"
	pbgopySymmetricKeyFileEnv = "PBGOPY_SYMMETRIC_KEY_FILE"

	defaultGPGExecutablePath = "gpg"
)

var errNotfound = errors.New("not found")

// CipherWithSessKey is used when hybrid encryption.
type CipherWithSessKey struct {
	EncryptedData       []byte `json:"encryptedData"`
	EncryptedSessionKey []byte `json:"encryptedSessionKey"`
}

// addBasicAuthHeader adds a Basic Auth Header if the auth flag is set.
func addBasicAuthHeader(req *http.Request, basicAuth string) {
	if basicAuth == "" {
		return
	}
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basicAuth)))
}

// readNoMoreThan reads at most, max bytes from reader.
// It returns an error if there is more data to be read.
func readNoMoreThan(r io.Reader, max int64) ([]byte, error) {
	var data bytes.Buffer
	n, err := data.ReadFrom(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, fmt.Errorf("input data exceeds set limit %dBytes", max)
	}
	return data.Bytes(), nil
}

// datasizeToBytes converts a datasize to its equivalent in bytes.
func datasizeToBytes(ds string) (int64, error) {
	var maxBufSizeBytes datasize.ByteSize
	if err := maxBufSizeBytes.UnmarshalText([]byte(ds)); err != nil {
		return 0, errors.Unwrap(err)
	}
	return int64(maxBufSizeBytes.Bytes()), nil
}

// getSymmetricKey retrieves the symmetric-key. First try to derive it from password.
// Then try to read the file. errNotFound is returned if key not found.
func getSymmetricKey(password, symmetricKeyFile string) ([]byte, error) {
	if password != "" && (symmetricKeyFile != "" || os.Getenv(pbgopySymmetricKeyFileEnv) != "") {
		return nil, fmt.Errorf("can't specify both password and key")
	}

	// Derive from password.
	if password != "" {
		// NOTE: This option is for cases where data cannot be shared between devices in advance.
		// Therefore nil is used as a salt though it cannot prevent a dictionary attack.
		return pbcrypto.DeriveKey(password, nil), nil
	}

	// Read from file.
	if symmetricKeyFile != "" {
		key, err := ioutil.ReadFile(symmetricKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", symmetricKeyFile, err)
		}
		return bytes.TrimSpace(key), nil
	}
	if os.Getenv(pbgopySymmetricKeyFileEnv) != "" {
		key, err := ioutil.ReadFile(os.Getenv(pbgopySymmetricKeyFileEnv))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", symmetricKeyFile, err)
		}
		return bytes.TrimSpace(key), nil
	}
	return nil, errNotfound
}
