package crypto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
)

// GPG works as a GPG client.
type GPG interface {
	// EncryptWithRecipient encrypts a given plaintext using a given user's public-key.
	EncryptWithRecipient(ctx context.Context, plaintext []byte, userID string) ([]byte, error)
	// DecryptWithRecipient decrypts a given encrypted data using a given user's private-key.
	DecryptWithRecipient(ctx context.Context, encrypted []byte, userID string) ([]byte, error)
}

type gpg struct {
	executable string
}

func NewGPG(executable string) GPG {
	return &gpg{
		executable: executable,
	}
}

func (g *gpg) EncryptWithRecipient(ctx context.Context, plaintext []byte, userID string) ([]byte, error) {
	return g.runGPGCommand(ctx, bytes.NewReader(plaintext), "--encrypt", "-r", userID)
}

func (g *gpg) DecryptWithRecipient(ctx context.Context, encrypted []byte, userID string) ([]byte, error) {
	return g.runGPGCommand(ctx, bytes.NewReader(encrypted), "--decrypt", "-r", userID)
}

func (g *gpg) runGPGCommand(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, g.executable, args...)
	cmd.Stdin = stdin
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run GPG: stderr: %s: err: %w", stderr.String(), err)
	}
	return stdout.Bytes(), nil
}
