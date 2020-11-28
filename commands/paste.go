package commands

import (
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

type pasteRunner struct {
	timeout time.Duration
	key     string

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
	cmd.Flags().StringVarP(&r.key, "key", "k", "", "Common key for encryption/decryption")
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
	res, err := client.Get(address)
	if err != nil {
		return fmt.Errorf("failed to issue get request: %w", err)
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read the response body: %w", err)
	}
	if r.key != "" {
		data, err = decrypt(r.key, data)
		if err != nil {
			return fmt.Errorf("failed to decrypt the data: %w", err)
		}
	}

	fmt.Fprint(r.stdout, string(data))
	return nil
}

func decrypt(key string, encryptedData []byte) ([]byte, error) {
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
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("invalid cipher test")
	}
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
