package commands

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

const dummyByteForKey = byte('-')

type copyRunner struct {
	timeout time.Duration
	key     string

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
	cmd.Flags().StringVarP(&r.key, "key", "k", "", "Common key for encryption/decryption")
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
	if r.key != "" {
		data, err = encrypt(r.key, data)
		if err != nil {
			return fmt.Errorf("failed to encrypt the data: %w", err)
		}
	}

	client := &http.Client{
		Timeout: r.timeout,
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

func encrypt(key string, data []byte) ([]byte, error) {
	k := []byte(key)
	length := len(k)
	if length > 32 {
		return nil, fmt.Errorf("the key size should be less than 32 bytes")
	}
	if length < 32 {
		// Fill it up with dummies
		n := 32 - length
		for i := 0; i < n; i++ {
			k = append(k, dummyByteForKey)
		}
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return encryptedData, nil
}
