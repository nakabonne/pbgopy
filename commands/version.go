package commands

import (
	"fmt"
	"io"
	"runtime"
	"strings"

	extver "github.com/linuxsuren/cobra-extension/version"
	"github.com/spf13/cobra"
)

func NewVersionCommand(stderr io.Writer) (cmd *cobra.Command) {
	const name = "pbgopy"
	cmd = extver.NewVersionCmd("nakabonne", name, name, func(ver string) string {
		if strings.HasPrefix(ver, "v") {
			ver = strings.TrimPrefix(ver, "v")
		}
		return fmt.Sprintf("https://github.com/nakabonne/pbgopy/releases/download/v%s/%s_%s_%s_%s.tar.gz",
			ver, name, ver, runtime.GOOS, runtime.GOARCH)
	})
	return
}
