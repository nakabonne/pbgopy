package commands

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"

	pbcrypto "github.com/nakabonne/pbgopy/crypto"
)

type copyRunner struct {
	timeout          time.Duration
	password         string
	symmetricKeyFile string
	basicAuth        string
	maxBufSize       string
	fromClipboard    bool

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
	cmd.Flags().StringVarP(&r.password, "password", "p", "", "Password to derive the symmetric-key to be used for encryption")
	cmd.Flags().StringVarP(&r.symmetricKeyFile, "symmetric-key-file", "k", "", "Path to symmetric-key file to be used for encryption")
	cmd.Flags().StringVarP(&r.basicAuth, "basic-auth", "a", "", "Basic authentication, username:password")
	cmd.Flags().StringVar(&r.maxBufSize, "max-size", "500mb", "Max data size with unit")
	cmd.Flags().BoolVarP(&r.fromClipboard, "from-clipboard", "c", false, "Put the data stored at local clipboard into pbgopy server")
	return cmd
}

func (r *copyRunner) run(_ *cobra.Command, _ []string) error {
	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		return fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}

	// Start reading data.
	var source io.Reader = os.Stdin
	if r.fromClipboard {
		clipboardData, err := clipboard.ReadAll()
		if err != nil {
			return err
		}
		source = strings.NewReader(clipboardData)
	}
	sizeInBytes, err := datasizeToBytes(r.maxBufSize)
	if err != nil {
		return fmt.Errorf("failed to parse data size: %w", err)
	}
	data, err := readNoMoreThan(source, sizeInBytes)
	if err != nil {
		return fmt.Errorf("failed to read from source: %w", err)
	}

	client := &http.Client{
		Timeout: r.timeout,
	}

	// Encryption with the user-specified way.
	key, err := getKey(r.password, r.symmetricKeyFile, func() ([]byte, error) {
		return r.regenerateSalt(client, address)
	})
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}
	if key != nil {
		data, err = pbcrypto.Encrypt(key, data)
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
