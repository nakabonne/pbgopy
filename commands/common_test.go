package commands

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadNoMoreThan(t *testing.T) {
	value := []byte("Foo Bar Baz")

	testCases := []struct {
		name   string
		reader io.Reader
		max    int64
		err    error
		value  []byte
	}{
		{
			name:   "TestExactLength",
			reader: bytes.NewReader(value),
			max:    11,
			value:  value,
		},
		{
			name:   "TestShortData",
			reader: bytes.NewReader(value),
			max:    20,
			value:  value,
		},
		{
			name:   "TestTooMuchData",
			reader: bytes.NewReader(value),
			max:    6,
			err:    fmt.Errorf("input data exceeds set limit 6Bytes"),
		},
		{
			name:   "TestNoData",
			reader: strings.NewReader(""),
			max:    6,
			value:  []byte(""),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			value, err := readNoMoreThan(tc.reader, tc.max)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.value, value)
		})
	}
}

func TestDatasizeToBytes(t *testing.T) {
	errInvalidSyntax := fmt.Errorf("invalid syntax")

	testCases := []struct {
		datasize    string
		err         error
		sizeInBytes int64
	}{
		{
			datasize:    "1B",
			sizeInBytes: 1,
		},
		{
			datasize:    "1000kb",
			sizeInBytes: 1000 * 1024,
		},
		{
			datasize:    "12mb",
			sizeInBytes: 12 * 1024 * 1024,
		},
		{
			datasize:    "1megabyte",
			sizeInBytes: 1 * 1024 * 1024,
		},
		{
			datasize: "1meg",
			err:      errInvalidSyntax,
		},
		{
			datasize: "-4mb",
			err:      errInvalidSyntax,
		},
		{
			datasize: "1.1kb",
			err:      errInvalidSyntax,
		},
	}

	for _, tc := range testCases {
		sizeInBytes, err := datasizeToBytes(tc.datasize)
		assert.Equal(t, tc.err, err)
		assert.Equal(t, tc.sizeInBytes, sizeInBytes)
	}
}
