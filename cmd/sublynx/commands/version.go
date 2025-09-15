package commands

import (
	"fmt"
	"runtime"
	"github.com/spf13/cobra"
)

func NewVersionCommand(version, commit, buildDate string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  `Print detailed version information about SubLynx.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("SubLynx Version: %s\n", version)
			fmt.Printf("Git Commit: %s\n", commit)
			fmt.Printf("Build Date: %s\n", buildDate)
			fmt.Printf("Go Version: %s\n", runtime.Version())
			fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}