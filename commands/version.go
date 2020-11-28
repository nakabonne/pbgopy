package commands

import (
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// Automatically populated by goreleaser during build
	version = "unversioned"
	commit  = "?"
	date    = "?"
)

func NewVersionCommand(stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the current version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(stderr, "version=%s, commit=%s, buildDate=%s, os=%s, arch=%s\n", version, commit, date, runtime.GOOS, runtime.GOARCH)
		},
	}
}
