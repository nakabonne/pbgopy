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

	"github.com/spf13/cobra"

	pbcrypto "github.com/nakabonne/pbgopy/crypto"
)

type copyRunner struct {
	timeout  time.Duration
	password string

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
	return cmd
}

func (r *copyRunner) run(_ *cobra.Command, _ []string) error {

	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		return fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}
	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read from STDIN: %w", err)
	}

	client := &http.Client{
		Timeout: r.timeout,
	}

	var password string

	if r.password != "" {
		password = r.password
	} else if os.Getenv(pbgopyPasswordFileEnv) != "" {
		password, err = getPasswordFromEnv(os.Getenv(pbgopyPasswordFileEnv))
		if err != nil {
			return err
		}
	}

	if len(password) != 0 {
		salt, err := regenerateSalt(client, address)
		if err != nil {
			return fmt.Errorf("failed to get salt: %w", err)
		}
		data, err = pbcrypto.Encrypt(password, salt, data)
		if err != nil {
			return fmt.Errorf("failed to encrypt the data: %w", err)
		}
	}

	req, err := http.NewRequest(http.MethodPut, address, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	if _, err := client.Do(req); err != nil {
		return fmt.Errorf("failed to issue request: %w", err)
	}
	return nil
}

func getPasswordFromEnv(fileLoc string) (string, error) {
	file, err := os.Open(fileLoc)
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

// regenerateSalt lets the server regenerate the salt and gives back the new one.
func regenerateSalt(client *http.Client, address string) ([]byte, error) {
	if strings.HasSuffix(address, "/") {
		address = address[:len(address)-1]
	}
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s%s", address, saltPath), bytes.NewBuffer([]byte{}))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue request: %w", err)
	}
	defer res.Body.Close()

	return ioutil.ReadAll(res.Body)
}
