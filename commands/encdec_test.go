package commands

import (
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
			cipherText, err = encrypt(tt.passForEnc, salt, data)
			require.NoError(t, err)
			plainText, err = decrypt(tt.passForDec, salt, cipherText)
			assert.Equal(t, tt.wantSuccess, err == nil)

			assert.Equal(t, tt.wantSuccess, string(data) == string(plainText))
		})
	}
}
