package commands

import (
	"os"
	"github.com/spf13/cobra"
)

func NewCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate the autocompletion script for the specified shell",
		Long: `To load completions:

Bash:
  $ source <(sublynx completion bash)
  # To load automatically on new shells, run:
  $ sublynx completion bash > /etc/bash_completion.d/sublynx

Zsh:
  $ sublynx completion zsh > "${fpath[1]}/_sublynx"

Fish:
  $ sublynx completion fish | source

PowerShell:
  PS> sublynx completion powershell | Out-String | Invoke-Expression
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return cobra.ErrSubCommandRequired
			}
		},
	}
	return cmd
}
