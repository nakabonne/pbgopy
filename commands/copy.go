package commands

import (
	"bytes"
	"context"
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
	gpgUserID        string
	gpgPath          string
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
	cmd.Flags().StringVarP(&r.gpgUserID, "gpg-user-id", "u", "", "GPG user id associated with public key to be used for encryption")
	cmd.Flags().StringVar(&r.gpgPath, "gpg-path", defaultGPGExecutablePath, "Path to gpg executable")
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

	// Start encryption.
	data, err = r.encrypt(data)
	if err != nil {
		return err
	}

	// Start issuing an HTTP request.
	client := &http.Client{
		Timeout: r.timeout,
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
//   - hybrid cryptosystem with a public-key
//   - symmetric-key encryption with a key derived from password
//   - symmetric-key encryption with an existing key
func (r *copyRunner) encrypt(plaintext []byte) ([]byte, error) {
	// Perform hybrid encryption with a public-key if specified.
	if r.publicKeyFile != "" || r.gpgUserID != "" {
		return r.encryptWithPubKey(plaintext)
	}

	// Try to encrypt with a symmetric-key.
	key, err := getSymmetricKey(r.password, r.symmetricKeyFile)
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

// NOTE: pbgopy provides two way to specify the public key. Specifying path directly or specifying via GPG.
// Either publicKeyFile or gpgUserID are required.
func (r *copyRunner) encryptWithPubKey(plaintext []byte) ([]byte, error) {
	if r.gpgUserID != "" && r.publicKeyFile != "" {
		return nil, fmt.Errorf("can't specify both \"--gpg-user-id\" and \"--public-key-file\"")
	}

	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("failed to gererate a session key: %w", err)
	}
	encrypted, err := pbcrypto.Encrypt(sessionKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt the plaintext: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Encrypt the session-key with the public-key.
	var encryptedSessKey []byte
	if r.gpgUserID != "" {
		gpg := pbcrypto.NewGPG(r.gpgPath)
		encryptedSessKey, err = gpg.EncryptWithRecipient(ctx, sessionKey, r.gpgUserID)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt the session key: %w", err)
		}
	}
	if r.publicKeyFile != "" {
		pubKey, err := ioutil.ReadFile(r.publicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", r.publicKeyFile, err)
		}
		encryptedSessKey, err = pbcrypto.EncryptWithRSA(sessionKey, pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt the session key: %w", err)
		}
	}

	return json.Marshal(&CipherWithSessKey{
		EncryptedData:       encrypted,
		EncryptedSessionKey: encryptedSessKey,
	})
}
