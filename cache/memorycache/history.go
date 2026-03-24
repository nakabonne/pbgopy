package memorycache

import (
	"sync"
	"time"

	"github.com/nakabonne/pbgopy/cache"
)

// HistoryCache wraps a Cache and adds clipboard history as a ring buffer.
type HistoryCache struct {
	cache.Cache
	mu      sync.RWMutex
	entries []cache.HistoryEntry
	maxSize int
	nextID  int
}

// NewHistoryCache creates a new HistoryCache wrapping the given cache.
// maxSize controls how many history entries are retained.
func NewHistoryCache(inner cache.Cache, maxSize int) *HistoryCache {
	if maxSize <= 0 {
		maxSize = 10
	}
	return &HistoryCache{
		Cache:   inner,
		entries: make([]cache.HistoryEntry, 0, maxSize),
		maxSize: maxSize,
		nextID:  1,
	}
}

// Append adds a new entry to the history and returns its ID.
func (h *HistoryCache) Append(data []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	entry := cache.HistoryEntry{
		ID:        h.nextID,
		Data:      dataCopy,
		Timestamp: time.Now().UnixNano(),
		Size:      len(data),
	}
	h.nextID++

	h.entries = append(h.entries, entry)
	if len(h.entries) > h.maxSize {
		h.entries = h.entries[len(h.entries)-h.maxSize:]
	}

	return entry.ID, nil
}

// List returns the most recent entries (newest first), up to limit.
func (h *HistoryCache) List(limit int) ([]cache.HistoryEntry, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	n := len(h.entries)
	if limit > 0 && limit < n {
		n = limit
	}

	// Return newest first.
	result := make([]cache.HistoryEntry, n)
	for i := 0; i < n; i++ {
		src := h.entries[len(h.entries)-1-i]
		result[i] = cache.HistoryEntry{
			ID:        src.ID,
			Timestamp: src.Timestamp,
			Size:      src.Size,
			// Omit Data in list to keep response small.
		}
	}
	return result, nil
}

// GetEntry returns a specific history entry by ID.
func (h *HistoryCache) GetEntry(id int) (*cache.HistoryEntry, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for i := range h.entries {
		if h.entries[i].ID == id {
			return &h.entries[i], nil
		}
	}
	return nil, cache.ErrNotFound
}
