package commands

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/nakabonne/pbgopy/cache"
	"github.com/nakabonne/pbgopy/cache/memorycache"
	pbcrypto "github.com/nakabonne/pbgopy/crypto"
)

const (
	defaultPort = 9090
	defaultTTL  = time.Hour * 24

	rootPath        = "/"
	saltPath        = "/salt"
	lastUpdatedPath = "/lastupdated"

	dataKey        = "data"
	saltKey        = "salt"
	lastUpdatedKey = "lastUpdated"
)

type serveRunner struct {
	port      int
	ttl       time.Duration
	basicAuth string

	// random data used as an additional input for hashing data.
	salt   []byte
	cache  cache.Cache
	stdout io.Writer
	stderr io.Writer
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
	return cmd
}

func (r *serveRunner) run(_ *cobra.Command, _ []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if r.ttl == 0 {
		r.cache = memorycache.NewCache()
	} else {
		r.cache = memorycache.NewTTLCache(ctx, r.ttl, r.ttl)
	}

	server := r.createServer()

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

func (r *serveRunner) createServer() *http.Server {
	// Start HTTP server
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", r.port),
		Handler: mux,
	}
	mux.HandleFunc(rootPath, r.basicAuthHandler(r.handle))
	mux.HandleFunc(saltPath, r.basicAuthHandler(r.handleSalt))
	mux.HandleFunc(lastUpdatedPath, r.handleLastUpdated)
	return server
}

func (r *serveRunner) handleLastUpdated(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		lastUpdated, err := r.cache.Get(lastUpdatedKey)
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

func (r *serveRunner) handle(w http.ResponseWriter, req *http.Request) {

	switch req.Method {
	case http.MethodGet:
		data, err := r.cache.Get(dataKey)
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
		if err := r.cache.Put(dataKey, body); err != nil {
			http.Error(w, fmt.Sprintf("Failed to cache: %v", err), http.StatusInternalServerError)
			return
		}
		if err := r.cache.Put(lastUpdatedKey, time.Now().UnixNano()); err != nil {
			http.Error(w, fmt.Sprintf("Failed to save lastUpdated timestamp: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, fmt.Sprintf("Method %s is not allowed", req.Method), http.StatusMethodNotAllowed)
	}
}

func (r *serveRunner) handleSalt(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		salt, err := r.cache.Get(saltKey)
		if err != nil {
			http.Error(w, "Failed to get salt from cache", http.StatusInternalServerError)
			return
		}
		if s, ok := salt.([]byte); ok {
			w.Write(s)
			return
		}
		http.Error(w, fmt.Sprintf("The cached data is unknown type: %T", salt), http.StatusInternalServerError)
	case http.MethodPut:
		salt := pbcrypto.RandomBytes(128)
		if err := r.cache.Put(saltKey, salt); err != nil {
			http.Error(w, fmt.Sprintf("Failed to cache: %v", err), http.StatusInternalServerError)
			return
		}
		w.Write(salt)
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
