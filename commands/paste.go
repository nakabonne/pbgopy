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
	timeout   time.Duration
	password  string
	basicAuth string

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
	cmd.Flags().StringVarP(&r.password, "password", "p", "", "Password for encryption/decryption")
	cmd.Flags().StringVarP(&r.basicAuth, "basic-auth", "a", "", "Basic authentication, username:password")
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
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read the response body: %w", err)
	}
	if r.password != "" {
		salt, err := r.getSalt(client, address)
		if err != nil {
			return fmt.Errorf("failed to get salt: %w", err)
		}
		data, err = pbcrypto.Decrypt(r.password, salt, data)
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
