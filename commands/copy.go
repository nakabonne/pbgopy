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
	timeout       time.Duration
	password      string
	basicAuth     string
	maxBufSize    string
	fromClipboard bool

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
	cmd.Flags().BoolVarP(&r.fromClipboard, "from-clipboard", "c", false, "Put the data stored at clipboard into pbgopy server")
	return cmd
}

func (r *copyRunner) run(_ *cobra.Command, _ []string) error {
	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		return fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}

	var data []byte

	if r.fromClipboard {
		clipboardData, err := clipboard.ReadAll()
		if err != nil {
			return err
		}
		data = []byte(clipboardData)

	} else {
		sizeInBytes, err := datasizeToBytes(r.maxBufSize)
		if err != nil {
			return fmt.Errorf("failed to parse data size: %w", err)
		}
		data, err = readNoMoreThan(os.Stdin, sizeInBytes)
		if err != nil {
			return fmt.Errorf("failed to read from STDIN: %w", err)
		}
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
