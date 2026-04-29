package commands

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	historyKindText      = "text"
	historyKindImage     = "image"
	historyKindBinary    = "binary"
	historyKindEncrypted = "encrypted"
	historyKindUnknown   = "unknown"

	historyPreviewRunes = 80
)

// HistoryEntry is the metadata returned by the history API.
type HistoryEntry struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Size      int       `json:"size"`
	Latest    bool      `json:"latest"`
	MIME      string    `json:"mime"`
	Kind      string    `json:"kind"`
	Preview   string    `json:"preview"`
	SHA256    string    `json:"sha256"`
}

type historyItem struct {
	HistoryEntry
	body      []byte
	expiresAt time.Time
}

type historyStore struct {
	mu        sync.Mutex
	entries   []*historyItem
	limit     int
	ttl       time.Duration
	everAdded bool
	now       func() time.Time
}

func newHistoryStore(limit int, ttl time.Duration) *historyStore {
	return &historyStore{
		limit: limit,
		ttl:   ttl,
		now:   time.Now,
	}
}

func (s *historyStore) Add(body []byte, encrypted bool) (*historyItem, error) {
	id, err := newHistoryID()
	if err != nil {
		return nil, err
	}

	now := s.now()
	item := &historyItem{
		HistoryEntry: newHistoryEntry(id, now, body, encrypted),
		body:         append([]byte(nil), body...),
	}
	if s.ttl > 0 {
		item.expiresAt = now.Add(s.ttl)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)
	s.entries = append([]*historyItem{item}, s.entries...)
	s.everAdded = true
	s.enforceLimitLocked()
	return item.copy(), nil
}

func (s *historyStore) List() []HistoryEntry {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)
	entries := make([]HistoryEntry, 0, len(s.entries))
	for i, item := range s.entries {
		entry := item.HistoryEntry
		entry.Latest = i == 0
		entries = append(entries, entry)
	}
	return entries
}

func (s *historyStore) Latest() (*historyItem, bool) {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)
	if len(s.entries) == 0 {
		return nil, false
	}
	item := s.entries[0].copy()
	item.Latest = true
	return item, true
}

func (s *historyStore) Get(id string) (*historyItem, bool) {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)
	for i, item := range s.entries {
		if item.ID == id {
			copied := item.copy()
			copied.Latest = i == 0
			return copied, true
		}
	}
	return nil, false
}

func (s *historyStore) Delete(id string) bool {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(now)
	for i, item := range s.entries {
		if item.ID == id {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			return true
		}
	}
	return false
}

func (s *historyStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries = nil
	s.everAdded = true
}

func (s *historyStore) EverAdded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.everAdded
}

func (s *historyStore) pruneExpiredLocked(now time.Time) {
	if s.ttl <= 0 {
		return
	}
	n := 0
	for _, item := range s.entries {
		if item.expiresAt.IsZero() || item.expiresAt.After(now) {
			s.entries[n] = item
			n++
		}
	}
	s.entries = s.entries[:n]
}

func (s *historyStore) enforceLimitLocked() {
	if s.limit <= 0 || len(s.entries) <= s.limit {
		return
	}
	s.entries = s.entries[:s.limit]
}

func (item *historyItem) copy() *historyItem {
	copied := *item
	copied.body = append([]byte(nil), item.body...)
	return &copied
}

func newHistoryID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate history id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func newHistoryEntry(id string, createdAt time.Time, body []byte, encrypted bool) HistoryEntry {
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	entry := HistoryEntry{
		ID:        id,
		CreatedAt: createdAt,
		Size:      len(body),
		MIME:      detectMIME(body),
		SHA256:    sha,
	}

	switch {
	case encrypted:
		entry.MIME = "application/octet-stream"
		entry.Kind = historyKindEncrypted
		entry.Preview = "encrypted sha256:" + sha[:8]
	case setImageMetadata(&entry, body):
	case isLikelyText(body):
		entry.Kind = historyKindText
		entry.Preview = textPreview(body)
	case entry.MIME == "":
		entry.Kind = historyKindUnknown
		entry.Preview = "unknown sha256:" + sha[:8]
	default:
		entry.Kind = historyKindBinary
		entry.Preview = "binary sha256:" + sha[:8]
	}
	return entry
}

func detectMIME(body []byte) string {
	sample := body
	if len(sample) > 512 {
		sample = sample[:512]
	}
	return http.DetectContentType(sample)
}

func setImageMetadata(entry *HistoryEntry, body []byte) bool {
	cfg, format, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		return false
	}
	entry.Kind = historyKindImage
	switch format {
	case "jpeg":
		entry.MIME = "image/jpeg"
		entry.Preview = fmt.Sprintf("JPEG image %dx%d", cfg.Width, cfg.Height)
	case "png":
		entry.MIME = "image/png"
		entry.Preview = fmt.Sprintf("PNG image %dx%d", cfg.Width, cfg.Height)
	case "gif":
		entry.MIME = "image/gif"
		entry.Preview = fmt.Sprintf("GIF image %dx%d", cfg.Width, cfg.Height)
	default:
		entry.Preview = fmt.Sprintf("%s image %dx%d", strings.ToUpper(format), cfg.Width, cfg.Height)
	}
	return true
}

func isLikelyText(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for _, r := range string(body) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func textPreview(body []byte) string {
	var b strings.Builder
	for _, r := range string(body) {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r):
			continue
		default:
			b.WriteRune(r)
		}
	}
	collapsed := strings.Join(strings.Fields(b.String()), " ")
	runes := []rune(collapsed)
	if len(runes) <= historyPreviewRunes {
		return collapsed
	}
	return string(runes[:historyPreviewRunes]) + "..."
}
