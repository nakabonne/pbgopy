package main

import (
	"fmt"
	"io"
	"os"

	"github.com/nakabonne/pbgopy/commands"

	"github.com/spf13/cobra"
)

type app struct {
	rootCmd *cobra.Command
	stdout  io.Writer
	stderr  io.Writer
}

func newApp(name, desc string, stdout, stderr io.Writer) *app {
	a := &app{
		rootCmd: &cobra.Command{
			Use:   name,
			Short: desc,
		},
		stdout: stdout,
		stderr: stderr,
	}
	return a
}

func (a *app) addCommands(cmds ...*cobra.Command) {
	for _, cmd := range cmds {
		a.rootCmd.AddCommand(cmd)
	}
}

func main() {
	a := newApp("pbgopy", "Copy and paste between devices", os.Stdout, os.Stderr)
	a.addCommands(
		commands.NewCopyCommand(a.stdout),
		commands.NewServeCommand(a.stdout),
	)

	if err := a.rootCmd.Execute(); err != nil {
		fmt.Fprintln(a.stderr, err)
		os.Exit(1)
	}
}
