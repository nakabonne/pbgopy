package crypto

import (
	"bytes"
	"context"
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
	cmd := exec.CommandContext(ctx, g.executable, args...)
	cmd.Stdin = stdin
	return cmd.Output()
}
