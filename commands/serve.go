package commands

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/nakabonne/pbgopy/cache"
	"github.com/nakabonne/pbgopy/cache/memorycache"
)

const (
	defaultPort = 9090
	defaultTTL  = time.Hour * 24

	cacheKey = "clipboard"
)

type serveRunner struct {
	port int
	ttl  time.Duration

	cache  cache.Cache
	stdout io.Writer
	stderr io.Writer
}

func NewServeCommand(stdout, stderr io.Writer) *cobra.Command {
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

	// Start HTTP server
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", r.port),
		Handler: mux,
	}
	mux.HandleFunc("/", r.handle)

	defer func() {
		fmt.Fprintf(r.stderr, "Start gracefully shutting down the server\n")
		if err := server.Shutdown(ctx); err != nil {
			fmt.Fprintf(r.stderr, "Failed to gracefully shut down the server: %v\n", err)
		}
	}()

	fmt.Fprintf(r.stderr, "Start listening on %d\n", r.port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(r.stderr, "Failed to start the server: %v\n", err)
		os.Exit(1)
	}
	return nil
}

func (r *serveRunner) handle(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		// TODO: handle get
	case http.MethodPut:
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "Bad request body", http.StatusBadRequest)
			return
		}
		if err := r.cache.Put(cacheKey, body); err != nil {
			http.Error(w, fmt.Sprintf("Failed to cache: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, fmt.Sprintf("Method %s is not allowed", req.Method), http.StatusMethodNotAllowed)
	}
}
