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
	"strings"
	"time"

	"github.com/c2h5oh/datasize"
	"github.com/spf13/cobra"

	pbcrypto "github.com/nakabonne/pbgopy/crypto"
)

type copyRunner struct {
	timeout    time.Duration
	password   string
	basicAuth  string
	maxBufSize string

	stdout io.Writer
	stderr io.Writer
}

func NewCopyCommand(stdout, stderr io.Writer) *cobra.Command {
	r := &copyRunner{
		stdout: stdout,
		stderr: stderr,
	}
	cmd := &cobra.Command{
		Use:   "copy",
		Short: "Copy from stdin",
		Example: `  export PBGOPY_SERVER=http://192.168.11.5:9090
  echo hello | pbgopy copy`,
		RunE: r.run,
	}
	cmd.Flags().DurationVar(&r.timeout, "timeout", 5*time.Second, "Time limit for requests")
	cmd.Flags().StringVarP(&r.password, "password", "p", "", "Password for encryption/decryption")
	cmd.Flags().StringVarP(&r.basicAuth, "basic-auth", "a", "", "Basic authentication, username:password")
	cmd.Flags().StringVar(&r.maxBufSize, "max-size", "500mb", "Max data size with unit")
	return cmd
}

func (r *copyRunner) run(_ *cobra.Command, _ []string) error {
	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		return fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}

	sizeInBytes, err := datasizeToBytes(r.maxBufSize)
	if err != nil {
		return fmt.Errorf("failed to parse data size: %w", err)
	}
	data, err := readNoMoreThan(os.Stdin, sizeInBytes)
	if err != nil {
		return fmt.Errorf("failed to read from STDIN: %w", err)
	}

	client := &http.Client{
		Timeout: r.timeout,
	}
	if r.password != "" {
		salt, err := r.regenerateSalt(client, address)
		if err != nil {
			return fmt.Errorf("failed to get salt: %w", err)
		}
		data, err = pbcrypto.Encrypt(r.password, salt, data)
		if err != nil {
			return fmt.Errorf("failed to encrypt the data: %w", err)
		}
	}

	req, err := http.NewRequest(http.MethodPut, address, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	addBasicAuthHeader(req, r.basicAuth)

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to issue request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed request: Status %s", res.Status)
	}

	return nil
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

// regenerateSalt lets the server regenerate the salt and gives back the new one.
func (r *copyRunner) regenerateSalt(client *http.Client, address string) ([]byte, error) {
	if strings.HasSuffix(address, "/") {
		address = address[:len(address)-1]
	}
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s%s", address, saltPath), bytes.NewBuffer([]byte{}))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	addBasicAuthHeader(req, r.basicAuth)
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue request: %w", err)
	}
	defer res.Body.Close()

	return ioutil.ReadAll(res.Body)
}

// addBasicAuthHeader adds a Basic Auth Header if the auth flag is set.
func addBasicAuthHeader(req *http.Request, basicAuth string) {
	if basicAuth != "" {
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basicAuth)))
	}
}
