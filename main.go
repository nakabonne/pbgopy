package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/nakabonne/pbgopy/commands"
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
		commands.NewCopyCommand(a.stdout, a.stderr),
		commands.NewPasteCommand(a.stdout, a.stderr),
		commands.NewServeCommand(a.stdout, a.stderr),
		commands.NewVersionCommand(a.stderr),
	)

	if err := a.rootCmd.Execute(); err != nil {
		fmt.Fprintln(a.stderr, err)
		os.Exit(1)
	}
}
