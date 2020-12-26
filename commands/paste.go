package commands

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	pbcrypto "github.com/nakabonne/pbgopy/crypto"
)

type pasteRunner struct {
	timeout          time.Duration
	password         string
	symmetricKeyFile string
	basicAuth        string
	maxBufSize       string

	stdout io.Writer
	stderr io.Writer
}

func NewPasteCommand(stdout, stderr io.Writer) *cobra.Command {
	r := &pasteRunner{
		stdout: stdout,
		stderr: stderr,
	}
	cmd := &cobra.Command{
		Use:   "paste",
		Short: "Paste to stdout",
		Example: `  export PBGOPY_SERVER=http://192.168.11.5:9090
  pbgopy paste >hello.txt`,
		RunE: r.run,
	}
	cmd.Flags().DurationVar(&r.timeout, "timeout", 5*time.Second, "Time limit for requests")
	cmd.Flags().StringVarP(&r.password, "password", "p", "", "Password to derive the symmetric-key to be used for decryption")
	cmd.Flags().StringVarP(&r.symmetricKeyFile, "symmetric-key-file", "k", "", "Path to symmetric-key file to be used for decryption")
	cmd.Flags().StringVarP(&r.basicAuth, "basic-auth", "a", "", "Basic authentication, username:password")
	cmd.Flags().StringVar(&r.maxBufSize, "max-size", "500mb", "Max data size with unit")
	return cmd
}

func (r *pasteRunner) run(_ *cobra.Command, _ []string) error {
	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		return fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}
	client := &http.Client{
		Timeout: r.timeout,
	}

	// Start reading data.
	req, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	addBasicAuthHeader(req, r.basicAuth)
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to issue get request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed request: Status %s", res.Status)
	}
	sizeInBytes, err := datasizeToBytes(r.maxBufSize)
	if err != nil {
		return fmt.Errorf("failed to parse data size: %w", err)
	}
	data, err := readNoMoreThan(res.Body, sizeInBytes)
	if err != nil {
		return fmt.Errorf("failed to read the response body: %w", err)
	}

	// Decryption with the user-specified way.
	key, err := getKey(r.password, r.symmetricKeyFile, func() ([]byte, error) {
		return r.getSalt(client, address)
	})
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}
	if key != nil {
		data, err = pbcrypto.Decrypt(key, data)
		if err != nil {
			return fmt.Errorf("failed to decrypt the data: %w", err)
		}
	}

	fmt.Fprint(r.stdout, string(data))
	return nil
}

// getSalt gives back the salt.
func (r *pasteRunner) getSalt(client *http.Client, address string) ([]byte, error) {
	if strings.HasSuffix(address, "/") {
		address = address[:len(address)-1]
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s%s", address, saltPath), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	addBasicAuthHeader(req, r.basicAuth)
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue get request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed request: Status %s", res.Status)
	}
	return ioutil.ReadAll(res.Body)
}
