package commands

import (
	"io"
	"time"

	"github.com/spf13/cobra"
)

type serveRunner struct {
	port   int
	ttl    time.Duration
	stdout io.Writer
}

func NewServeCommand(stdout io.Writer) *cobra.Command {
	r := &serveRunner{
		stdout: stdout,
	}
	cmd := &cobra.Command{
		Use:     "serve",
		Short:   "Start the server that acts like a clipboard",
		Example: "pbgopy serve --port=9090 --ttl=10m",
		RunE:    r.run,
	}

	cmd.Flags().IntVarP(&r.port, "port", "p", 9090, "The port the server listens on")
	cmd.Flags().DurationVar(&r.ttl, "ttl", time.Hour*24, "The time that the contents is stored. Give 0s for disabling TTL")
	return cmd
}

func (r *serveRunner) run(_ *cobra.Command, _ []string) error {
	return nil
}
