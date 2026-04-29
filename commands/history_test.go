package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nakabonne/pbgopy/cache/memorycache"
)

func TestHistoryDefaultLimitPreservesLatestBehavior(t *testing.T) {
	handler := newHistoryTestHandler(defaultHistoryLimit, 0)

	putClipboard(t, handler, []byte("first"), false)
	entries := getHistory(t, handler)
	if len(entries) != 1 {
		t.Fatalf("history length: got %d want 1", len(entries))
	}
	firstID := entries[0].ID

	putClipboard(t, handler, []byte("second"), false)
	entries = getHistory(t, handler)
	if len(entries) != 1 {
		t.Fatalf("history length: got %d want 1", len(entries))
	}
	if entries[0].Preview != "second" || !entries[0].Latest {
		t.Fatalf("latest entry: got %+v", entries[0])
	}

	rr := serveHistoryRequest(t, handler, http.MethodGet, "/", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET / status: got %d want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Body.String(); got != "second" {
		t.Fatalf("GET / body: got %q want %q", got, "second")
	}

	rr = serveHistoryRequest(t, handler, http.MethodGet, historyPath+"/"+firstID, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("old entry status: got %d want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHistoryLimitPasteByIDAndBinaryRoundTrip(t *testing.T) {
	handler := newHistoryTestHandler(3, 0)
	binary := []byte{0x00, 0xff, 0x10, 0x20, 0x7f}

	putClipboard(t, handler, []byte("first"), false)
	putClipboard(t, handler, binary, false)
	putClipboard(t, handler, []byte("third"), false)

	entries := getHistory(t, handler)
	if len(entries) != 3 {
		t.Fatalf("history length: got %d want 3", len(entries))
	}
	if entries[0].Preview != "third" || entries[1].Kind != historyKindBinary || entries[2].Preview != "first" {
		t.Fatalf("unexpected history order or metadata: %+v", entries)
	}

	rr := serveHistoryRequest(t, handler, http.MethodGet, "/", nil)
	if got := rr.Body.String(); got != "third" {
		t.Fatalf("latest body: got %q want %q", got, "third")
	}

	rr = serveHistoryRequest(t, handler, http.MethodGet, historyPath+"/"+entries[1].ID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("history entry status: got %d want %d", rr.Code, http.StatusOK)
	}
	if !bytes.Equal(rr.Body.Bytes(), binary) {
		t.Fatalf("binary body: got %v want %v", rr.Body.Bytes(), binary)
	}
}

func TestHistoryMetadataPreviewKinds(t *testing.T) {
	now := time.Date(2026, 4, 29, 10, 0, 0, 0, time.FixedZone("JST", 9*60*60))

	text := newHistoryEntry("text", now, []byte("hello\n\tworld   "+strings.Repeat("x", 100)), false)
	if text.Kind != historyKindText {
		t.Fatalf("text kind: got %q want %q", text.Kind, historyKindText)
	}
	if strings.ContainsAny(text.Preview, "\n\t\r\x1b") {
		t.Fatalf("text preview contains terminal-unsafe characters: %q", text.Preview)
	}
	if !strings.HasPrefix(text.Preview, "hello world ") || !strings.HasSuffix(text.Preview, "...") {
		t.Fatalf("text preview: got %q", text.Preview)
	}

	control := newHistoryEntry("control", now, []byte("hello\x1b[31mred"), false)
	if control.Kind != historyKindBinary {
		t.Fatalf("control kind: got %q want %q", control.Kind, historyKindBinary)
	}
	if strings.Contains(control.Preview, "\x1b") || strings.Contains(control.Preview, "hello") {
		t.Fatalf("control preview is not safe: %q", control.Preview)
	}

	imageEntry := newHistoryEntry("image", now, testPNG(t, 2, 3), false)
	if imageEntry.Kind != historyKindImage || imageEntry.MIME != "image/png" || imageEntry.Preview != "PNG image 2x3" {
		t.Fatalf("image metadata: got %+v", imageEntry)
	}

	binary := []byte{0x00, 0xff, 0x10, 0x20}
	binaryEntry := newHistoryEntry("binary", now, binary, false)
	if binaryEntry.Kind != historyKindBinary {
		t.Fatalf("binary kind: got %q want %q", binaryEntry.Kind, historyKindBinary)
	}
	if binaryEntry.Preview != "binary sha256:"+shaPrefix(binary) {
		t.Fatalf("binary preview: got %q", binaryEntry.Preview)
	}

	encrypted := newHistoryEntry("encrypted", now, []byte("secret plaintext"), true)
	if encrypted.Kind != historyKindEncrypted {
		t.Fatalf("encrypted kind: got %q want %q", encrypted.Kind, historyKindEncrypted)
	}
	if strings.Contains(encrypted.Preview, "secret") || encrypted.Preview != "encrypted sha256:"+shaPrefix([]byte("secret plaintext")) {
		t.Fatalf("encrypted preview exposes data or has wrong hash: %q", encrypted.Preview)
	}
}

func TestHistoryEncryptedServerEntryDoesNotExposePlaintext(t *testing.T) {
	handler := newHistoryTestHandler(3, 0)
	putClipboard(t, handler, []byte("secret plaintext"), true)

	entries := getHistory(t, handler)
	if len(entries) != 1 {
		t.Fatalf("history length: got %d want 1", len(entries))
	}
	if entries[0].Kind != historyKindEncrypted {
		t.Fatalf("encrypted kind: got %q want %q", entries[0].Kind, historyKindEncrypted)
	}
	if strings.Contains(entries[0].Preview, "secret") || entries[0].Preview != "encrypted sha256:"+shaPrefix([]byte("secret plaintext")) {
		t.Fatalf("encrypted preview exposes data or has wrong hash: %q", entries[0].Preview)
	}
}

func TestHistoryListExcludesExpiredEntries(t *testing.T) {
	base := time.Date(2026, 4, 29, 10, 0, 0, 0, time.UTC)
	now := base
	store := newHistoryStore(10, time.Second)
	store.now = func() time.Time { return now }

	item, err := store.Add([]byte("expired"), false)
	if err != nil {
		t.Fatal(err)
	}
	now = base.Add(2 * time.Second)

	if entries := store.List(); len(entries) != 0 {
		t.Fatalf("history length after expiration: got %d want 0", len(entries))
	}
	if _, ok := store.Get(item.ID); ok {
		t.Fatalf("expired entry should not be pasteable")
	}
	if _, ok := store.Latest(); ok {
		t.Fatalf("expired entry should not be latest")
	}
}

func TestHistoryDeleteEntry(t *testing.T) {
	handler := newHistoryTestHandler(3, 0)
	putClipboard(t, handler, []byte("old"), false)
	putClipboard(t, handler, []byte("new"), false)

	entries := getHistory(t, handler)
	rr := serveHistoryRequest(t, handler, http.MethodDelete, historyPath+"/"+entries[0].ID, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status: got %d want %d", rr.Code, http.StatusNoContent)
	}

	entries = getHistory(t, handler)
	if len(entries) != 1 || entries[0].Preview != "old" || !entries[0].Latest {
		t.Fatalf("history after delete: %+v", entries)
	}
	rr = serveHistoryRequest(t, handler, http.MethodGet, "/", nil)
	if got := rr.Body.String(); got != "old" {
		t.Fatalf("latest after delete: got %q want %q", got, "old")
	}

	rr = serveHistoryRequest(t, handler, http.MethodDelete, historyPath+"/missing", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing delete status: got %d want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHistoryClear(t *testing.T) {
	handler := newHistoryTestHandler(3, 0)
	putClipboard(t, handler, []byte("old"), false)
	putClipboard(t, handler, []byte("new"), false)

	rr := serveHistoryRequest(t, handler, http.MethodDelete, historyPath, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("clear status: got %d want %d", rr.Code, http.StatusNoContent)
	}
	if entries := getHistory(t, handler); len(entries) != 0 {
		t.Fatalf("history length after clear: got %d want 0", len(entries))
	}
	rr = serveHistoryRequest(t, handler, http.MethodGet, "/", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET / after clear: got %d want %d", rr.Code, http.StatusNotFound)
	}
}

func TestPasteRunnerPasteByID(t *testing.T) {
	handler := newHistoryTestHandler(3, 0)
	putClipboard(t, handler, []byte("first"), false)
	putClipboard(t, handler, []byte("second"), false)
	entries := getHistory(t, handler)

	t.Setenv(pbgopyServerEnv, "http://pbgopy.test")

	var stdout bytes.Buffer
	r := &pasteRunner{
		timeout:    time.Second,
		maxBufSize: "500mb",
		id:         entries[1].ID,
		stdout:     &stdout,
		client:     newHandlerClient(handler),
	}
	if err := r.run(nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "first" {
		t.Fatalf("paste --id output: got %q want %q", got, "first")
	}
}

func TestHistoryRunnerListJSON(t *testing.T) {
	handler := newHistoryTestHandler(3, 0)
	putClipboard(t, handler, []byte("first"), false)

	t.Setenv(pbgopyServerEnv, "http://pbgopy.test")

	var stdout bytes.Buffer
	r := &historyRunner{
		timeout:    time.Second,
		jsonOutput: true,
		stdout:     &stdout,
		client:     newHandlerClient(handler),
	}
	if err := r.list(nil, nil); err != nil {
		t.Fatal(err)
	}

	var entries []HistoryEntry
	if err := json.Unmarshal(stdout.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Preview != "first" || !entries[0].Latest {
		t.Fatalf("json history output: %+v", entries)
	}
}

func newHistoryTestHandler(limit int, ttl time.Duration) http.Handler {
	r := &serveRunner{
		cache:        memorycache.NewCache(),
		historyLimit: limit,
		ttl:          ttl,
	}
	return r.newServer().Handler
}

func putClipboard(t *testing.T, handler http.Handler, body []byte, encrypted bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))
	if encrypted {
		req.Header.Set(historyEncryptedHeader, "true")
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT / status: got %d want %d body %q", rr.Code, http.StatusOK, rr.Body.String())
	}
}

func getHistory(t *testing.T, handler http.Handler) []HistoryEntry {
	t.Helper()
	rr := serveHistoryRequest(t, handler, http.MethodGet, historyPath, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /history status: got %d want %d body %q", rr.Code, http.StatusOK, rr.Body.String())
	}
	var entries []HistoryEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	return entries
}

func serveHistoryRequest(t *testing.T, handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func testPNG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func shaPrefix(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:8]
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newHandlerClient(handler http.Handler) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			return rr.Result(), nil
		}),
	}
}
