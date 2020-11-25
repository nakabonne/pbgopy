package commands

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

type copyRunner struct {
	stdout io.Writer
}

func NewCopyCommand(stdout io.Writer) *cobra.Command {
	r := &copyRunner{
		stdout: stdout,
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
	contents := make([]rune, 0)
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _, err := reader.ReadRune()
		if err != nil && err == io.EOF {
			break
		}
		contents = append(contents, input)
	}
	// TODO: POST
	fmt.Fprintln(r.stdout, string(contents))
	return nil
}
