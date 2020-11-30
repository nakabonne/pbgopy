package crypt

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name        string
		passForEnc  string
		passForDec  string
		wantSuccess bool
	}{
		{
			name:        "wrong password given",
			passForEnc:  "password",
			passForDec:  "wrong-password",
			wantSuccess: false,
		},
		{
			name:        "right password given",
			passForEnc:  "password",
			passForDec:  "password",
			wantSuccess: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				data       = []byte("data")
				salt       = []byte("salt")
				cipherText = []byte{}
				plainText  = []byte{}
				err        error
			)
			cipherText, err = Encrypt(tt.passForEnc, salt, data)
			require.NoError(t, err)
			plainText, err = Decrypt(tt.passForDec, salt, cipherText)
			assert.Equal(t, tt.wantSuccess, err == nil)

			assert.Equal(t, tt.wantSuccess, string(data) == string(plainText))
		})
	}
}

func TestRandomBytes(t *testing.T) {
	validator := func(bs []byte) error {
		for _, b := range bs {
			if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
				continue
			}
			return fmt.Errorf("invalid character: %#U", b)
		}
		return nil
	}

	s1 := RandomBytes(10)
	assert.Equal(t, 10, len(s1))
	assert.NoError(t, validator(s1))

	s2 := RandomBytes(10)
	assert.Equal(t, 10, len(s2))
	assert.NoError(t, validator(s2))

	assert.NotEqual(t, s1, s2)
}
