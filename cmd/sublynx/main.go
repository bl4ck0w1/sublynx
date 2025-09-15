package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sort"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/bl4ck0w1/sublynx/cmd/sublynx/commands"
	"github.com/bl4ck0w1/sublynx/pkg/utils"
)

var (
	version   = "1.0.0"
	commit    = "unknown"
	buildDate = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "sublynx",
	Short: "SubLynx - Advanced Subdomain Discovery Platform",
	Long:  "SubLynx is a next-generation subdomain enumeration tool designed with Expert-level precision and enterprise-grade reliability.",
	Version: version,
	SilenceUsage:  true, 
	SilenceErrors: true, 
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := initConfig(); err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		if err := initLogging(); err != nil {
			return err
		}

		if err := ensureDirs(); err != nil {
			logrus.Warnf("Failed to ensure directories: %v", err)
		}

		if !viper.GetBool("quiet") {
			printBanner()
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default is $HOME/.sublynx/config.yaml)")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "quiet mode (no banner output)")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (text, json)")
	rootCmd.PersistentFlags().String("log-file", "", "log file path")

	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	_ = viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	_ = viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("log_format", rootCmd.PersistentFlags().Lookup("log-format"))
	_ = viper.BindPFlag("log_file", rootCmd.PersistentFlags().Lookup("log-file"))

	rootCmd.AddCommand(commands.NewScanCommand())
	rootCmd.AddCommand(commands.NewConfigureCommand())
	rootCmd.AddCommand(commands.NewOutputCommand())
	rootCmd.AddCommand(commands.NewVersionCommand(version, commit, buildDate))
	// rootCmd.AddCommand(commands.NewCompletionCommand())
	rootCmd.AddCommand(commands.NewStatsCommand())

	rootCmd.InitDefaultCompletionCmd()
	installConsolidatedHelp(rootCmd)

	rootCmd.SetVersionTemplate(fmt.Sprintf("Sublynx %s (commit %s, built %s)\n", version, commit, buildDate))
}

func initConfig() error {
	setDefaults()
	viper.SetEnvPrefix("SUBLYNX")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	if cfgFile := viper.GetString("config"); cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		viper.AddConfigPath(filepath.Join(home, ".sublynx"))
		viper.AddConfigPath("/etc/sublynx/")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			logrus.Warnf("Failed reading config file: %v", err)
		}
	} else {
		logrus.Debugf("Using config file: %s", viper.ConfigFileUsed())
	}

	return nil
}

func setDefaults() {
	viper.SetDefault("log_level", "info")
	viper.SetDefault("log_format", "json")
	viper.SetDefault("quiet", false)
	viper.SetDefault("max_concurrent_scans", 5)
	viper.SetDefault("default_timeout", "30m")
	viper.SetDefault("output_directory", "./reports")
	viper.SetDefault("data_directory", "./data")
	viper.SetDefault("temp_directory", "/tmp/sublynx")
}

func initLogging() error {
	logConfig := utils.LogConfig{
		Level:         viper.GetString("log_level"),
		Format:        viper.GetString("log_format"),
		FileLocation:  viper.GetString("log_file"),
		EnableConsole: true,
	}

	logger, err := utils.NewLogger(logConfig, "sublynx", version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize structured logger, falling back: %v\n", err)
		basic := logrus.New()
		basic.SetFormatter(&logrus.JSONFormatter{})
		logrus.SetOutput(basic.Out)
		logrus.SetLevel(logrus.InfoLevel)
		logrus.SetFormatter(basic.Formatter)
		return nil
	}

	logrus.SetOutput(logger.Out)
	logrus.SetLevel(logger.Level)
	logrus.SetFormatter(logger.Formatter)

	for _, hooks := range logger.Hooks {
		for _, h := range hooks {
			logrus.AddHook(h)
		}
	}
	return nil
}

func ensureDirs() error {
	dirs := []string{
		viper.GetString("output_directory"),
		viper.GetString("data_directory"),
		viper.GetString("temp_directory"),
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if err := utils.EnsureDir(d); err != nil {
			return fmt.Errorf("ensure dir %s: %w", d, err)
		}
	}
	return nil
}

func printBanner() {
	const banner = `

echo "   ▄████████ ███    █▄  ▀█████████▄   ▄█       ▄██   ▄   ███▄▄▄▄   ▀████    ▐████▀ ";
echo "  ███    ███ ███    ███   ███    ███ ███       ███   ██▄ ███▀▀▀██▄   ███▌   ████▀  ";
echo "  ███    █▀  ███    ███   ███    ███ ███       ███▄▄▄███ ███   ███    ███  ▐███    ";
echo "  ███        ███    ███  ▄███▄▄▄██▀  ███       ▀▀▀▀▀▀███ ███   ███    ▀███▄███▀    ";
echo "▀███████████ ███    ███ ▀▀███▀▀▀██▄  ███       ▄██   ███ ███   ███    ████▀██▄     ";
echo "         ███ ███    ███   ███    ██▄ ███       ███   ███ ███   ███   ▐███  ▀███    ";
echo "   ▄█    ███ ███    ███   ███    ███ ███▌    ▄ ███   ███ ███   ███  ▄███     ███▄  ";
echo " ▄████████▀  ████████▀  ▄█████████▀  █████▄▄██  ▀█████▀   ▀█   █▀  ████       ███▄ ";
echo "                                     ▀                                             ";
	

						Advanced Subdomain Discovery Platform
			______________________________________________________________
`
	fmt.Printf(banner, version)
	fmt.Printf("Build: %s (%s) | %s/%s\n\n", commit, buildDate, runtime.GOOS, runtime.GOARCH)
}

func installConsolidatedHelp(root *cobra.Command) {
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd != root {
			defaultHelp(cmd, args)
			return
		}

		if !viper.GetBool("quiet") {
			printBanner()
		}

		fmt.Println("USAGE:")
		fmt.Println("  sublynx [command] [global flags]\n")
		fmt.Println("GLOBAL FLAGS:")
		home, _ := os.UserHomeDir()
		fmt.Printf("  -c, --config string      config file (default is %s)\n", filepath.Join(home, ".sublynx", "config.yaml"))
		fmt.Printf("  -q, --quiet              quiet mode (no banner output)\n")
		fmt.Printf("  -l, --log-level string   log level (debug, info, warn, error, fatal) (default %q)\n", viper.GetString("log_level"))
		fmt.Printf("      --log-format string  log format (text, json) (default %q)\n", viper.GetString("log_format"))
		fmt.Printf("      --log-file string    log file path\n")
		fmt.Printf("  -v, --version            version for sublynx\n\n")

		cmds := []*cobra.Command{}
		for _, c := range root.Commands() {
			if c.IsAvailableCommand() && !c.Hidden {
				cmds = append(cmds, c)
			}
		}
		sort.Slice(cmds, func(i, j int) bool { return cmds[i].Name() < cmds[j].Name() })
		fmt.Println("COMMANDS OVERVIEW:")
		for _, c := range cmds {
			fmt.Printf("  %-12s %s\n", c.Name(), c.Short)
		}
		fmt.Println()

		fmt.Println("DETAILED COMMAND HELP")
		fmt.Println("─────────────────")

		for _, c := range cmds {
			fmt.Printf("\n%s\n", c.Name())
			fmt.Println(strings.Repeat("-", len(c.Name())))

			switch {
			case c.Long != "":
				fmt.Println(c.Long)
			case c.Short != "":
				fmt.Println(c.Short)
			}

			fmt.Println("\nUsage:")
			fmt.Printf("  sublynx %s\n\n", c.UseLine())

			if c.Flags().HasAvailableFlags() {
				fmt.Println("Flags:")
				c.Flags().PrintDefaults()
				fmt.Println()
			}

			subs := []*cobra.Command{}
			for _, sc := range c.Commands() {
				if sc.IsAvailableCommand() && !sc.Hidden {
					subs = append(subs, sc)
				}
			}
			if len(subs) > 0 {
				fmt.Println("Subcommands:")
				for _, sc := range subs {
					title := c.Name() + " " + sc.Name()
					fmt.Printf("\n%s\n", title)
					fmt.Println(strings.Repeat("-", len(title)))

					if sc.Short != "" {
						fmt.Println(sc.Short)
						fmt.Println()
					}

					fmt.Println("Usage:")
					fmt.Printf("  sublynx %s %s\n\n", c.Name(), sc.UseLine())

					if sc.Flags().HasAvailableFlags() {
						fmt.Println("Flags:")
						sc.Flags().PrintDefaults()
						fmt.Println()
					}
				}
			}
		}

		fmt.Println("NOTES:")
		fmt.Println("  • Use \"sublynx [command] --help\" for focused help on any command.")
		fmt.Println("  • Autocomplete instructions are printed by `sublynx completion --help`.")
	})
}

func main() {
	startTime := time.Now()
	Execute()
	if strings.EqualFold(viper.GetString("log_level"), "debug") {
		logrus.Debugf("Execution completed in %v", time.Since(startTime))
	}
}
