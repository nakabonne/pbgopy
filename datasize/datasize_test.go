// Copyright (c) 2016 Maciej Lisiewski

package datasize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalText(t *testing.T) {
	table := []struct {
		in   ByteSize
		want string
	}{
		{0, "0B"},
		{B, "1B"},
		{KB, "1KB"},
		{MB, "1MB"},
		{GB, "1GB"},
		{TB, "1TB"},
		{PB, "1PB"},
		{EB, "1EB"},
		{400 * TB, "400TB"},
		{2048 * MB, "2GB"},
		{B + KB, "1025B"},
		{MB + 20*KB, "1044KB"},
		{100*MB + KB, "102401KB"},
	}

	for _, tt := range table {
		b, _ := tt.in.MarshalText()
		out := string(b)
		assert.Equal(t, tt.want, out)
	}
}

func TestUnmarshalText(t *testing.T) {
	table := []struct {
		in      string
		wantErr bool
		want    ByteSize
	}{
		{"0", false, ByteSize(0)},
		{"0B", false, ByteSize(0)},
		{"0 KB", false, ByteSize(0)},
		{"1", false, B},
		{"1K", false, KB},
		{"2MB", false, 2 * MB},
		{"5 GB", false, 5 * GB},
		{"20480 G", false, 20 * TB},
		{"50 eB", true, ByteSize((1 << 64) - 1)},
		{"200000 pb", true, ByteSize((1 << 64) - 1)},
		{"10 Mb", true, ByteSize(0)},
		{"g", true, ByteSize(0)},
		{"10 kB ", false, 10 * KB},
		{"10 kBs ", true, ByteSize(0)},
	}

	for _, tt := range table {
		var out ByteSize
		err := out.UnmarshalText([]byte(tt.in))
		assert.Equal(t, tt.wantErr, err != nil)
		assert.Equal(t, tt.want, out)
	}
}
