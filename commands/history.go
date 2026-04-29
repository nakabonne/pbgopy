package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type historyRunner struct {
	timeout    time.Duration
	basicAuth  string
	jsonOutput bool

	stdout io.Writer
	stderr io.Writer
	client *http.Client
}

func NewHistoryCommand(stdout, stderr io.Writer) *cobra.Command {
	r := &historyRunner{
		stdout: stdout,
		stderr: stderr,
	}
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List clipboard history",
		Example: `  export PBGOPY_SERVER=http://host.xz:9090
  pbgopy history
  pbgopy history --json
  pbgopy history delete <entry-id>
  pbgopy history clear`,
		RunE: r.list,
	}
	cmd.PersistentFlags().DurationVar(&r.timeout, "timeout", 5*time.Second, "Time limit for requests")
	cmd.PersistentFlags().StringVarP(&r.basicAuth, "basic-auth", "a", "", "Basic authentication, username:password")
	cmd.Flags().BoolVar(&r.jsonOutput, "json", false, "Output history metadata as JSON")

	cmd.AddCommand(&cobra.Command{
		Use:   "delete <entry-id>",
		Short: "Delete a history entry",
		Args:  cobra.ExactArgs(1),
		RunE:  r.delete,
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Delete all history entries",
		Args:  cobra.NoArgs,
		RunE:  r.clear,
	})
	return cmd
}

func (r *historyRunner) list(_ *cobra.Command, _ []string) error {
	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		return fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}

	res, err := r.do(http.MethodGet, historyURL(address))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return failedRequestError(res)
	}

	var entries []HistoryEntry
	if err := json.NewDecoder(res.Body).Decode(&entries); err != nil {
		return fmt.Errorf("failed to decode history: %w", err)
	}

	if r.jsonOutput {
		enc := json.NewEncoder(r.stdout)
		return enc.Encode(entries)
	}
	return writeHistoryTable(r.stdout, entries, time.Now())
}

func (r *historyRunner) delete(_ *cobra.Command, args []string) error {
	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		return fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}

	res, err := r.do(http.MethodDelete, historyEntryURL(address, args[0]))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return failedRequestError(res)
	}
	return nil
}

func (r *historyRunner) clear(_ *cobra.Command, _ []string) error {
	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		return fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}

	res, err := r.do(http.MethodDelete, historyURL(address))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return failedRequestError(res)
	}
	return nil
}

func (r *historyRunner) do(method, url string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	addBasicAuthHeader(req, r.basicAuth)
	res, err := r.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue request: %w", err)
	}
	return res, nil
}

func (r *historyRunner) httpClient() *http.Client {
	if r.client != nil {
		return r.client
	}
	return &http.Client{
		Timeout: r.timeout,
	}
}

func writeHistoryTable(w io.Writer, entries []HistoryEntry, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tAGE\tTYPE\tSIZE\tLATEST\tPREVIEW"); err != nil {
		return err
	}
	for _, entry := range entries {
		latest := ""
		if entry.Latest {
			latest = "*"
		}
		preview := entry.Preview
		if entry.Kind == historyKindText {
			preview = strconv.Quote(preview)
		}
		if _, err := fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			entry.ID,
			formatHistoryAge(now.Sub(entry.CreatedAt)),
			historyDisplayType(entry),
			formatHistorySize(entry.Size),
			latest,
			preview,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func historyDisplayType(entry HistoryEntry) string {
	switch entry.Kind {
	case historyKindEncrypted, historyKindBinary, historyKindUnknown:
		return entry.Kind
	}
	if entry.MIME != "" {
		return entry.MIME
	}
	if entry.Kind != "" {
		return entry.Kind
	}
	return historyKindUnknown
}

func formatHistoryAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
}

func formatHistorySize(size int) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(size)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value = value / 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d%s", size, units[unit])
	}
	return strings.TrimSuffix(fmt.Sprintf("%.1f", value), ".0") + units[unit]
}
