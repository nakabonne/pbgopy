package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name        string
		keyForEnc   string
		keyForDec   string
		wantSuccess bool
	}{
		{
			name:        "wrong key given",
			keyForEnc:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			keyForDec:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			wantSuccess: false,
		},
		{
			name:        "right key given",
			keyForEnc:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			keyForDec:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantSuccess: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				data       = []byte("data")
				cipherText = []byte{}
				plainText  = []byte{}
				err        error
			)
			cipherText, err = Encrypt([]byte(tt.keyForEnc), data)
			require.NoError(t, err)
			plainText, err = Decrypt([]byte(tt.keyForDec), cipherText)
			assert.Equal(t, tt.wantSuccess, err == nil)

			assert.Equal(t, tt.wantSuccess, string(data) == string(plainText))
		})
	}
}
