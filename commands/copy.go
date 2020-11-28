package commands

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

type copyRunner struct {
	stdout io.Writer
	stderr io.Writer
}

func NewCopyCommand(stdout, stderr io.Writer) *cobra.Command {
	r := &copyRunner{
		stdout: stdout,
		stderr: stderr,
	}
	cmd := &cobra.Command{
		Use:     "copy",
		Short:   "Copy from stdin",
		Example: "echo hello | pbgopy copy",
		RunE:    r.run,
	}

	return cmd
}

func (r *copyRunner) run(_ *cobra.Command, _ []string) error {
	address := os.Getenv(pbgopyServerEnv)
	if address == "" {
		fmt.Errorf("put the pbgopy server's address into %s environment variable", pbgopyServerEnv)
	}
	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read from STDIN: %w", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPut, address, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	if _, err := client.Do(req); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	return nil
}
