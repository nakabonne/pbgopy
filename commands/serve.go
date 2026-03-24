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
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/nakabonne/pbgopy/cache"
	"github.com/nakabonne/pbgopy/cache/memorycache"
)

const (
	defaultPort       = 9090
	defaultTTL        = time.Hour * 24
	defaultMaxHistory = 10

	rootPath        = "/"
	lastUpdatedPath = "/lastupdated"
	historyPath     = "/history"
	historyItemPath = "/history/"

	dataCacheKey        = "data"
	lastUpdatedCacheKey = "lastUpdated"
)

type serveRunner struct {
	port       int
	ttl        time.Duration
	basicAuth  string
	maxHistory int

	cache        cache.Cache
	historyCache *memorycache.HistoryCache
	stdout       io.Writer
	stderr       io.Writer
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
		Example: "pbgopy serve --port=9090 --ttl=10m",
		RunE:    r.run,
	}

	cmd.Flags().IntVarP(&r.port, "port", "p", defaultPort, "The port the server listens on")
	cmd.Flags().DurationVar(&r.ttl, "ttl", defaultTTL, "The time that the contents is stored. Give 0s for disabling TTL")
	cmd.Flags().StringVarP(&r.basicAuth, "basic-auth", "a", "", "Basic authentication, username:password")
	cmd.Flags().IntVar(&r.maxHistory, "max-history", defaultMaxHistory, "Max number of clipboard history entries to retain")
	return cmd
}

func (r *serveRunner) run(_ *cobra.Command, _ []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var inner cache.Cache
	if r.ttl == 0 {
		inner = memorycache.NewCache()
	} else {
		inner = memorycache.NewTTLCache(ctx, r.ttl, r.ttl)
	}
	r.cache = inner
	r.historyCache = memorycache.NewHistoryCache(inner, r.maxHistory)

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
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", r.port),
		Handler: mux,
	}
	mux.HandleFunc(rootPath, r.basicAuthHandler(r.handle))
	mux.HandleFunc(lastUpdatedPath, r.basicAuthHandler(r.handleLastUpdated))
	mux.HandleFunc(historyPath, r.basicAuthHandler(r.handleHistory))
	mux.HandleFunc(historyItemPath, r.basicAuthHandler(r.handleHistoryItem))
	return server
}

func (r *serveRunner) handle(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
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
		if err := r.cache.Put(dataCacheKey, body); err != nil {
			http.Error(w, fmt.Sprintf("Failed to cache: %v", err), http.StatusInternalServerError)
			return
		}
		if err := r.cache.Put(lastUpdatedCacheKey, time.Now().UnixNano()); err != nil {
			http.Error(w, fmt.Sprintf("Failed to save lastUpdated timestamp: %v", err), http.StatusInternalServerError)
			return
		}
		if r.historyCache != nil {
			if _, err := r.historyCache.Append(body); err != nil {
				log.Printf("Failed to append to history: %v\n", err)
			}
		}
		w.WriteHeader(http.StatusOK)
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

func (r *serveRunner) handleHistory(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		if r.historyCache == nil {
			http.Error(w, "History not available", http.StatusNotFound)
			return
		}
		limit := r.maxHistory
		if l := req.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		entries, err := r.historyCache.List(limit)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to list history: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	default:
		http.Error(w, fmt.Sprintf("Method %s is not allowed", req.Method), http.StatusMethodNotAllowed)
	}
}

func (r *serveRunner) handleHistoryItem(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		if r.historyCache == nil {
			http.Error(w, "History not available", http.StatusNotFound)
			return
		}
		idStr := strings.TrimPrefix(req.URL.Path, historyItemPath)
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "Invalid history ID", http.StatusBadRequest)
			return
		}
		entry, err := r.historyCache.GetEntry(id)
		if errors.Is(err, cache.ErrNotFound) {
			http.Error(w, "History entry not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get history entry: %v", err), http.StatusInternalServerError)
			return
		}
		w.Write(entry.Data)
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
