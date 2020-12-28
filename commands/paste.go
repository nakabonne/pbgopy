package commands

import (
	"bytes"
	"encoding/json"
	"errors"
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
	timeout                time.Duration
	password               string
	symmetricKeyFile       string
	privateKeyFile         string
	privateKeyPasswordFile string
	basicAuth              string
	maxBufSize             string

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
	cmd.Flags().StringVarP(&r.privateKeyFile, "private-key-file", "K", "", "Path to an RSA private-key file to be used for decryption; Must be in PEM or DER format")
	cmd.Flags().StringVar(&r.privateKeyPasswordFile, "private-key-password-file", "", "Path to password file to decrypt the encrypted private key")
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

	data, err = r.decrypt(data, func() ([]byte, error) {
		return r.getSalt(client, address)
	})
	if err != nil {
		return err
	}

	fmt.Fprint(r.stdout, string(data))
	return nil
}

// decrypts with the user-specified way. It directly gives back the given data if any key doesn't exists.
// The order of priority is:
//   - hybrid encryption with a public-key
//   - symmetric-key encryption with a key derived from password
//   - symmetric-key encryption with an existing key
func (r *pasteRunner) decrypt(data []byte, saltFunc func() ([]byte, error)) ([]byte, error) {
	if r.privateKeyFile != "" {
		withSessKey := &CipherWithSessKey{}
		if err := json.Unmarshal(data, withSessKey); err != nil {
			return nil, fmt.Errorf("failed to decode data: %w", err)
		}
		privKey, err := ioutil.ReadFile(r.privateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", r.privateKeyFile, err)
		}
		var keyPassword []byte
		if r.privateKeyPasswordFile != "" {
			keyPassword, err = ioutil.ReadFile(r.privateKeyPasswordFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read %s: %w", r.privateKeyPasswordFile, err)
			}
		}
		sessKey, err := pbcrypto.DecryptWithRSA(withSessKey.EncryptedSessionKey, privKey, bytes.TrimSpace(keyPassword))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt the session key: %w", err)
		}
		plaintext, err := pbcrypto.Decrypt(sessKey, withSessKey.EncryptedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt the encrypted data: %w", err)
		}
		return plaintext, nil
	}

	key, err := getSymmetricKey(r.password, r.symmetricKeyFile, saltFunc)
	if errors.Is(err, errNotfound) {
		return data, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	plaintext, err := pbcrypto.Decrypt(key, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the data: %w", err)
	}
	return plaintext, nil
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
