package memorycache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nakabonne/pbgopy/cache"
)

func TestHistoryCache_Append(t *testing.T) {
	inner := NewCache()
	h := NewHistoryCache(inner, 3)

	id1, err := h.Append([]byte("first"))
	require.NoError(t, err)
	assert.Equal(t, 1, id1)

	id2, err := h.Append([]byte("second"))
	require.NoError(t, err)
	assert.Equal(t, 2, id2)
}

func TestHistoryCache_List(t *testing.T) {
	inner := NewCache()
	h := NewHistoryCache(inner, 5)

	h.Append([]byte("aaa"))
	h.Append([]byte("bbb"))
	h.Append([]byte("ccc"))

	entries, err := h.List(10)
	require.NoError(t, err)
	assert.Len(t, entries, 3)
	// Newest first.
	assert.Equal(t, 3, entries[0].ID)
	assert.Equal(t, 2, entries[1].ID)
	assert.Equal(t, 1, entries[2].ID)
	// Data is omitted in list.
	assert.Nil(t, entries[0].Data)
}

func TestHistoryCache_ListWithLimit(t *testing.T) {
	inner := NewCache()
	h := NewHistoryCache(inner, 10)

	for i := 0; i < 5; i++ {
		h.Append([]byte("data"))
	}

	entries, err := h.List(2)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, 5, entries[0].ID)
	assert.Equal(t, 4, entries[1].ID)
}

func TestHistoryCache_GetEntry(t *testing.T) {
	inner := NewCache()
	h := NewHistoryCache(inner, 5)

	h.Append([]byte("hello"))
	h.Append([]byte("world"))

	entry, err := h.GetEntry(1)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), entry.Data)
	assert.Equal(t, 5, entry.Size)

	entry, err = h.GetEntry(2)
	require.NoError(t, err)
	assert.Equal(t, []byte("world"), entry.Data)

	_, err = h.GetEntry(99)
	assert.Equal(t, cache.ErrNotFound, err)
}

func TestHistoryCache_RingBuffer(t *testing.T) {
	inner := NewCache()
	h := NewHistoryCache(inner, 3)

	h.Append([]byte("one"))
	h.Append([]byte("two"))
	h.Append([]byte("three"))
	h.Append([]byte("four")) // Should evict "one".

	entries, err := h.List(10)
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	// "one" (ID 1) should be gone.
	_, err = h.GetEntry(1)
	assert.Equal(t, cache.ErrNotFound, err)

	// "two" (ID 2) should still exist.
	entry, err := h.GetEntry(2)
	require.NoError(t, err)
	assert.Equal(t, []byte("two"), entry.Data)
}

func TestHistoryCache_DelegatesCache(t *testing.T) {
	inner := NewCache()
	h := NewHistoryCache(inner, 5)

	// The underlying Cache interface should still work.
	err := h.Put("key", "value")
	require.NoError(t, err)

	v, err := h.Get("key")
	require.NoError(t, err)
	assert.Equal(t, "value", v)
}
