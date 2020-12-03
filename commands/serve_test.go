package commands

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/nakabonne/pbgopy/cache/memorycache"
)

func TestServerCopy(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache}

	handler := r.createServer().Handler

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

	if v, err := cache.Get(dataKey); err != nil || !reflect.DeepEqual(v.([]byte), []byte("clipboardValue")) {
		t.Errorf("Cache was not populated with clipboard: got value: %s err: %v", string(v.([]byte)), err)
	}
}

func TestServerCopyBasicAuth_validCredentials(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache, basicAuth: "testUser:testPass"}

	handler := r.createServer().Handler

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

	if v, err := cache.Get(dataKey); err != nil || !reflect.DeepEqual(v.([]byte), []byte("clipboardValue")) {
		t.Errorf("Cache was not populated with clipboard: got value: %s err: %v", string(v.([]byte)), err)
	}
}

func TestServerCopyBasicAuth_invalidCredentials(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache, basicAuth: "testUser:testPass"}

	handler := r.createServer().Handler

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

	_, err = cache.Get(dataKey)
	if err == nil {
		t.Errorf("expected an error, got none")
	}
}

func TestServerPaste(t *testing.T) {
	cache := memorycache.NewCache()
	r := &serveRunner{cache: cache}
	_ = cache.Put(dataKey, []byte("clipboardValue"))

	handler := r.createServer().Handler

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
	_ = cache.Put(dataKey, []byte("clipboardValue"))

	handler := r.createServer().Handler

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
	_ = cache.Put(dataKey, []byte("clipboardValue"))

	handler := r.createServer().Handler

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
