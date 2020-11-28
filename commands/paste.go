package commands

import (
	"io"

	"github.com/spf13/cobra"
)

type pasteRunner struct {
	stdout io.Writer
	stderr io.Writer
}

func NewPasteCommand(stdout, stderr io.Writer) *cobra.Command {
	r := &pasteRunner{
		stdout: stdout,
		stderr: stderr,
	}
	cmd := &cobra.Command{
		Use:     "paste",
		Short:   "Paste to stdout",
		Example: "pbgopy paste >hello.txt",
		RunE:    r.run,
	}

	return cmd
}

func (r *pasteRunner) run(_ *cobra.Command, _ []string) error {
	return nil
}
