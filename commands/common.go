package commands

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/nakabonne/pbgopy/datasize"
)

const (
	pbgopyServerEnv       = "PBGOPY_SERVER"
	pbgopyPasswordFileEnv = "PBGOPY_PASSWORD_FILE"
)

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

// getPasswordFromFile returns the password stored in the provided filepath.
func getPasswordFromFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open password file: %w", err)
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("unable to get file information: %w", err)
	}

	passBuf := make([]byte, fileInfo.Size())

	_, err = io.ReadFull(file, passBuf)
	if err != nil {
		return "", fmt.Errorf("unable to read file: %w", err)
	}

	return string(passBuf), nil
}
