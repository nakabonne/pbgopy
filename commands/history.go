package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/nakabonne/pbgopy/cache"
)

type historyRunner struct {
	timeout   time.Duration
	basicAuth string

	stdout io.Writer
	stderr io.Writer
}

func NewHistoryCommand(stdout, stderr io.Writer) *cobra.Command {
	r := &historyRunner{
		stdout: stdout,
		stderr: stderr,
	}
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show clipboard history",
		Example: `  export PBGOPY_SERVER=http://host.xz:9090
  pbgopy history
  pbgopy history 3`,
		RunE: r.run,
	}
	cmd.Flags().DurationVar(&r.timeout, "timeout", 5*time.Second, "Time limit for requests")
	cmd.Flags().StringVarP(&r.basicAuth, "basic-auth", "a", "", "Basic authentication, username:password")
	return cmd
}

func (r *historyRunner) run(_ *cobra.Command, args []string) error {
	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		return fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}

	client := &http.Client{
		Timeout: r.timeout,
	}

	// If an ID argument is provided, fetch that specific entry.
	if len(args) > 0 {
		return r.getEntry(client, address, args[0])
	}

	// Otherwise list history.
	return r.listHistory(client, address)
}

func (r *historyRunner) listHistory(client *http.Client, address string) error {
	req, err := http.NewRequest(http.MethodGet, address+"/history", nil)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	addBasicAuthHeader(req, r.basicAuth)

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to issue request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed request: Status %s", res.Status)
	}

	var entries []cache.HistoryEntry
	if err := json.NewDecoder(res.Body).Decode(&entries); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if len(entries) == 0 {
		fmt.Fprintln(r.stdout, "No history entries")
		return nil
	}

	for _, e := range entries {
		t := time.Unix(0, e.Timestamp)
		fmt.Fprintf(r.stdout, "  %d\t%s\t%d bytes\n", e.ID, t.Format("2006-01-02 15:04:05"), e.Size)
	}
	return nil
}

func (r *historyRunner) getEntry(client *http.Client, address, id string) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/history/%s", address, id), nil)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	addBasicAuthHeader(req, r.basicAuth)

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to issue request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed request: Status %s", res.Status)
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	fmt.Fprint(r.stdout, string(data))
	return nil
}
