package commands

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/nakabonne/pbgopy/cache/memorycache"
)

func TestLastUpdatedGet(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache}

	handler := r.newServer().Handler

	req, err := http.NewRequest("PUT", "/", strings.NewReader("clipboardValue"))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Get timestamp back
	req, err = http.NewRequest("GET", "/lastupdated", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	v, err := cache.Get(lastUpdatedCacheKey)
	if err != nil {
		t.Fatal("Cache was not populated with timestamp")
	}

	lu, ok := v.(int64)
	if !ok {
		t.Errorf("Could not retrieve lastUpdated timestamp from cache for type %T", v)
	}

	respValue := rr.Body.String()
	if fmt.Sprintf("%d", lu) != respValue {
		t.Errorf("expected timestamp %d, got %s", lu, respValue)
	}
}

func TestServerCopy(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache}

	handler := r.newServer().Handler

	req, err := http.NewRequest("PUT", "/", strings.NewReader("clipboardValue"))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if v, err := cache.Get(dataCacheKey); err != nil || !reflect.DeepEqual(v.([]byte), []byte("clipboardValue")) {
		t.Errorf("Cache was not populated with clipboard: got value: %s err: %v", string(v.([]byte)), err)
	}
}

func TestServerCopyBasicAuth_validCredentials(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache, basicAuth: "testUser:testPass"}

	handler := r.newServer().Handler

	req, err := http.NewRequest("PUT", "/", strings.NewReader("clipboardValue"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testUser:testPass")))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if v, err := cache.Get(dataCacheKey); err != nil || !reflect.DeepEqual(v.([]byte), []byte("clipboardValue")) {
		t.Errorf("Cache was not populated with clipboard: got value: %s err: %v", string(v.([]byte)), err)
	}
}

func TestServerCopyBasicAuth_invalidCredentials(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache, basicAuth: "testUser:testPass"}

	handler := r.newServer().Handler

	req, err := http.NewRequest("PUT", "/", strings.NewReader("clipboardValue"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testUser:invalidPass")))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}

	_, err = cache.Get(dataCacheKey)
	if err == nil {
		t.Errorf("expected an error, got none")
	}
}

func TestServerPaste(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache}
	_ = cache.Put(dataCacheKey, []byte("clipboardValue"))

	handler := r.newServer().Handler

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "clipboardValue"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestServerPasteBasicAuth_validCredentials(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache, basicAuth: "testUser:testPass"}
	_ = cache.Put(dataCacheKey, []byte("clipboardValue"))

	handler := r.newServer().Handler

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testUser:testPass")))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "clipboardValue"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestServerPasteBasicAuth_invalidCredentials(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache, basicAuth: "testUser:testPass"}
	_ = cache.Put(dataCacheKey, []byte("clipboardValue"))

	handler := r.newServer().Handler

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testUser:invalidPass")))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}

	notExpected := "clipboardValue"
	if rr.Body.String() == notExpected {
		t.Errorf("handler returned unexpected body: got %v but wanted Unauthorized", rr.Body.String())
	}
}
