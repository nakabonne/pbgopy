package commands

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	publicKeyFile    string
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
	cmd.Flags().StringVarP(&r.publicKeyFile, "public-key-file", "K", "", "Path to an RSA public-key file to be used for encryption; Must be in PEM or DER format")
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

	data, err = r.encrypt(data, func() ([]byte, error) {
		return r.regenerateSalt(client, address)
	})
	if err != nil {
		return err
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

// encrypts with the user-specified way. It directly gives back plaintext if any key doesn't exists.
// The order of priority is:
//   - hybrid encryption with a public-key
//   - symmetric-key encryption with a key derived from password
//   - symmetric-key encryption with an existing key
func (r *copyRunner) encrypt(plaintext []byte, saltFunc func() ([]byte, error)) ([]byte, error) {
	if r.publicKeyFile != "" {
		sessionKey := make([]byte, 32)
		if _, err := rand.Read(sessionKey); err != nil {
			return nil, fmt.Errorf("failed to gererate a session key: %w", err)
		}
		encrypted, err := pbcrypto.Encrypt(sessionKey, plaintext)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt the plaintext: %w", err)
		}
		// Encrypt the session-key with the public-key.
		pubKey, err := ioutil.ReadFile(r.publicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", r.publicKeyFile, err)
		}
		encryptedSessKey, err := pbcrypto.EncryptWithRSA(pubKey, sessionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt the session key: %w", err)
		}
		withKey, err := json.Marshal(&CipherWithSessKey{
			EncryptedData:       encrypted,
			EncryptedSessionKey: encryptedSessKey,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to encode data with session-key: %w", err)
		}
		return withKey, nil
	}

	key, err := getSymmetricKey(r.password, r.symmetricKeyFile, saltFunc)
	if errors.Is(err, errNotfound) {
		return plaintext, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	encrypted, err := pbcrypto.Encrypt(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt the plaintext: %w", err)
	}
	return encrypted, nil
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
