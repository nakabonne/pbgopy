package commands

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

	s1 := randomBytes(10)
	assert.Equal(t, 10, len(s1))
	assert.NoError(t, validator(s1))

	s2 := randomBytes(10)
	assert.Equal(t, 10, len(s2))
	assert.NoError(t, validator(s2))

	assert.NotEqual(t, s1, s2)
}
