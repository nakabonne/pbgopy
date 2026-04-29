package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/nakabonne/pbgopy/cache"
	"github.com/nakabonne/pbgopy/cache/memorycache"
)

const (
	defaultPort         = 9090
	defaultTTL          = time.Hour * 24
	defaultHistoryLimit = 1

	rootPath        = "/"
	lastUpdatedPath = "/lastupdated"
	historyPath     = "/history"

	dataCacheKey        = "data"
	lastUpdatedCacheKey = "lastUpdated"

	historyEncryptedHeader = "X-Pbgopy-Encrypted"
)

type serveRunner struct {
	port         int
	ttl          time.Duration
	historyLimit int
	basicAuth    string

	cache   cache.Cache
	history *historyStore
	stdout  io.Writer
	stderr  io.Writer
}

func NewServeCommand(stdout, stderr io.Writer) *cobra.Command {
	log.SetOutput(stdout)
	r := &serveRunner{
		stdout: stdout,
		stderr: stderr,
	}
	cmd := &cobra.Command{
		Use:     "serve",
		Short:   "Start the server that acts like a clipboard",
		Example: "pbgopy serve --port=9090 --ttl=10m --history-limit=20",
		RunE:    r.run,
	}

	cmd.Flags().IntVarP(&r.port, "port", "p", defaultPort, "The port the server listens on")
	cmd.Flags().DurationVar(&r.ttl, "ttl", defaultTTL, "The time that the contents is stored. Give 0s for disabling TTL")
	cmd.Flags().IntVar(&r.historyLimit, "history-limit", defaultHistoryLimit, "Number of clipboard entries to retain. Give 0 for unlimited history")
	cmd.Flags().StringVarP(&r.basicAuth, "basic-auth", "a", "", "Basic authentication, username:password")
	return cmd
}

func (r *serveRunner) run(_ *cobra.Command, _ []string) error {
	if r.historyLimit < 0 {
		return fmt.Errorf("history-limit must be greater than or equal to 0")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if r.ttl == 0 {
		r.cache = memorycache.NewCache()
	} else {
		r.cache = memorycache.NewTTLCache(ctx, r.ttl, r.ttl)
	}
	r.history = newHistoryStore(r.historyLimit, r.ttl)

	server := r.newServer()
	defer func() {
		log.Println("Start gracefully shutting down the server")
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Failed to gracefully shut down the server: %v\n", err)
		}
	}()

	log.Printf("Start listening on %d\n", r.port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start the server: %w", err)
	}
	return nil
}

func (r *serveRunner) newServer() *http.Server {
	r.ensureCache()
	r.ensureHistoryStore()
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", r.port),
		Handler: mux,
	}
	mux.HandleFunc(historyPath, r.basicAuthHandler(r.handleHistory))
	mux.HandleFunc(historyPath+"/", r.basicAuthHandler(r.handleHistoryEntry))
	mux.HandleFunc(rootPath, r.basicAuthHandler(r.handle))
	mux.HandleFunc(lastUpdatedPath, r.basicAuthHandler(r.handleLastUpdated))
	return server
}

func (r *serveRunner) ensureCache() {
	if r.cache == nil {
		r.cache = memorycache.NewCache()
	}
}

func (r *serveRunner) ensureHistoryStore() {
	if r.history == nil {
		r.history = newHistoryStore(r.historyLimit, r.ttl)
	}
}

func (r *serveRunner) handle(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		if item, ok := r.history.Latest(); ok {
			w.Write(item.body)
			return
		}
		if r.history.EverAdded() {
			http.Error(w, "The data not found", http.StatusNotFound)
			return
		}
		data, err := r.cache.Get(dataCacheKey)
		if errors.Is(err, cache.ErrNotFound) {
			http.Error(w, "The data not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "Failed to get data from cache", http.StatusInternalServerError)
			return
		}
		if d, ok := data.([]byte); ok {
			w.Write(d)
			return
		}
		http.Error(w, fmt.Sprintf("The cached data is unknown type: %T", data), http.StatusInternalServerError)
	case http.MethodPut:
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "Bad request body", http.StatusBadRequest)
			return
		}
		encrypted := req.Header.Get(historyEncryptedHeader) == "true"
		if _, err := r.history.Add(body, encrypted); err != nil {
			http.Error(w, fmt.Sprintf("Failed to save history: %v", err), http.StatusInternalServerError)
			return
		}
		if err := r.cache.Put(dataCacheKey, body); err != nil {
			http.Error(w, fmt.Sprintf("Failed to cache: %v", err), http.StatusInternalServerError)
			return
		}
		if err := r.cache.Put(lastUpdatedCacheKey, time.Now().UnixNano()); err != nil {
			http.Error(w, fmt.Sprintf("Failed to save lastUpdated timestamp: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, fmt.Sprintf("Method %s is not allowed", req.Method), http.StatusMethodNotAllowed)
	}
}

func (r *serveRunner) handleHistory(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(r.history.List()); err != nil {
			http.Error(w, "Failed to encode history", http.StatusInternalServerError)
			return
		}
	case http.MethodDelete:
		r.history.Clear()
		_ = r.cache.Delete(dataCacheKey)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, fmt.Sprintf("Method %s is not allowed", req.Method), http.StatusMethodNotAllowed)
	}
}

func (r *serveRunner) handleHistoryEntry(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, historyPath+"/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "The history entry id is invalid", http.StatusBadRequest)
		return
	}

	switch req.Method {
	case http.MethodGet:
		item, ok := r.history.Get(id)
		if !ok {
			http.Error(w, "The history entry not found", http.StatusNotFound)
			return
		}
		if item.MIME != "" {
			w.Header().Set("Content-Type", item.MIME)
		}
		w.Write(item.body)
	case http.MethodDelete:
		if !r.history.Delete(id) {
			http.Error(w, "The history entry not found", http.StatusNotFound)
			return
		}
		if item, ok := r.history.Latest(); ok {
			_ = r.cache.Put(dataCacheKey, item.body)
		} else {
			_ = r.cache.Delete(dataCacheKey)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, fmt.Sprintf("Method %s is not allowed", req.Method), http.StatusMethodNotAllowed)
	}
}

func (r *serveRunner) handleLastUpdated(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		lastUpdated, err := r.cache.Get(lastUpdatedCacheKey)
		if errors.Is(err, cache.ErrNotFound) {
			http.Error(w, "The lastUpdated not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "Failed to get lastUpdated timestamp from cache", http.StatusInternalServerError)
			return
		}
		if lu, ok := lastUpdated.(int64); ok {
			fmt.Fprintf(w, "%d", lu)
			return
		}
		http.Error(w, fmt.Sprintf("The lastUpdated timestamp is unknown type: %T", lastUpdated), http.StatusInternalServerError)
	default:
		http.Error(w, fmt.Sprintf("Method %s is not allowed", req.Method), http.StatusMethodNotAllowed)
	}
}

// basicAuthHandler wraps a handler, enforcing basic authentication if the basic auth flag is set.
func (r *serveRunner) basicAuthHandler(handler http.HandlerFunc) http.HandlerFunc {
	if r.basicAuth == "" {
		return func(w http.ResponseWriter, r *http.Request) {
			handler(w, r)
		}
	}
	return func(w http.ResponseWriter, req *http.Request) {
		user, pass, ok := req.BasicAuth()
		if !ok || r.basicAuth != user+":"+pass {
			w.WriteHeader(401)
			_, _ = w.Write([]byte("Unauthorized.\n"))
			return
		}

		handler(w, req)
	}
}
