package commands

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func NewConfigureCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Manage SubLynx configuration",
		Long: `Manage SubLynx configuration profiles, view current settings,
and initialize configuration files.`,
	}

	cmd.AddCommand(newConfigureInitCommand())
	cmd.AddCommand(newConfigureShowCommand())
	cmd.AddCommand(newConfigureListCommand())
	cmd.AddCommand(newConfigureSetCommand())
	cmd.AddCommand(newConfigureGetCommand())
	return cmd
}

func newConfigureInitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init [profile]",
		Short: "Initialize a new configuration profile",
		Long:  `Initialize a new configuration profile with default values (YAML).`,
		Args:  cobra.MaximumNArgs(1),
		RunE:  runConfigureInit,
	}
}

func newConfigureShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show [profile]",
		Short: "Show current configuration",
		Long:  `Show the current configuration values for the specified profile.`,
		Args:  cobra.MaximumNArgs(1),
		RunE:  runConfigureShow,
	}
	cmd.Flags().StringP("profile", "p", "default", "Configuration profile")
	_ = viper.BindPFlag("configure.profile", cmd.Flags().Lookup("profile"))
	return cmd
}

func newConfigureListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available configuration profiles",
		Long:  `List all available configuration profiles (YAML files).`,
		RunE:  runConfigureList,
	}
}

func newConfigureSetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Long: `Set a configuration value for the selected profile.
Supports dotted keys (e.g. "scan.methods") and basic type parsing:
- booleans: true/false
- integers/floats: 10, 3.14
- durations (for keys containing timeout|interval|retention|delay): "30m", "10s"
- string lists: "a,b,c" -> ["a","b","c"]`,
		Args: cobra.ExactArgs(2),
		RunE: runConfigureSet,
	}
	cmd.Flags().StringP("profile", "p", "default", "Configuration profile")
	_ = viper.BindPFlag("configure.profile", cmd.Flags().Lookup("profile"))
	return cmd
}

func newConfigureGetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <key>",
		Short: "Get a configuration value",
		Long:  `Get a configuration value from the selected profile.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runConfigureGet,
	}
	cmd.Flags().StringP("profile", "p", "default", "Configuration profile")
	_ = viper.BindPFlag("configure.profile", cmd.Flags().Lookup("profile"))
	return cmd
}

func runConfigureInit(cmd *cobra.Command, args []string) error {
	profile := "default"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		profile = strings.TrimSpace(args[0])
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}

	configDir := filepath.Join(home, ".sublynx")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configFile := filepath.Join(configDir, profile+".yaml")

	if _, err := os.Stat(configFile); err == nil {
		logrus.Warnf("Configuration file already exists: %s", configFile)
		ok, ierr := confirmOverwrite()
		if ierr != nil {
			return ierr
		}
		if !ok {
			logrus.Info("Configuration initialization cancelled")
			return nil
		}
	}

	defaultConfig := getDefaultConfig()

	if err := writeYAMLFile(configFile, defaultConfig); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	logrus.Infof("Configuration initialized: %s", configFile)
	logrus.Info("Edit this file to customize defaults. Run `sublynx configure show -p " + profile + "` to view.")
	return nil
}

func runConfigureShow(cmd *cobra.Command, args []string) error {
	profile := viper.GetString("configure.profile")
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		profile = strings.TrimSpace(args[0])
	}

	if err := loadProfileIntoViper(profile); err != nil {
		return fmt.Errorf("failed to load profile %s: %w", profile, err)
	}

	fmt.Printf("Configuration for profile: %s\n", profile)
	fmt.Println("═══════════════════════════════════════════════════════════════")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "GENERAL SETTINGS:\t")
	fmt.Fprintf(w, "  Log Level:\t%s\n", viper.GetString("log_level"))
	fmt.Fprintf(w, "  Log Format:\t%s\n", viper.GetString("log_format"))
	fmt.Fprintf(w, "  Max Concurrent Scans:\t%d\n", viper.GetInt("max_concurrent_scans"))
	fmt.Fprintf(w, "  Default Timeout:\t%s\n", viper.GetString("default_timeout"))
	fmt.Fprintf(w, "  Output Directory:\t%s\n", viper.GetString("output_directory"))
	fmt.Fprintf(w, "  Data Directory:\t%s\n", viper.GetString("data_directory"))
	fmt.Fprintf(w, "  Temp Directory:\t%s\n", viper.GetString("temp_directory"))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "SCAN SETTINGS:\t")
	fmt.Fprintf(w, "  Methods:\t%v\n", viper.GetStringSlice("scan.methods"))
	fmt.Fprintf(w, "  Validation:\t%v\n", viper.GetStringSlice("scan.validation"))
	fmt.Fprintf(w, "  Depth:\t%d\n", viper.GetInt("scan.depth"))
	fmt.Fprintf(w, "  Stealth Mode:\t%t\n", viper.GetBool("scan.stealth"))
	fmt.Fprintf(w, "  Profile:\t%s\n", viper.GetString("scan.config_profile"))
	fmt.Fprintln(w)

	_ = w.Flush()
	return nil
}

func runConfigureList(cmd *cobra.Command, args []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	configDir := filepath.Join(home, ".subnlynx")

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		logrus.Info("No configuration profiles found.")
		logrus.Info("Run 'subnlynx configure init' to create a default profile.")
		return nil
	}

	files, err := filepath.Glob(filepath.Join(configDir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("failed to list configuration files: %w", err)
	}

	if len(files) == 0 {
		logrus.Info("No configuration profiles found.")
		return nil
	}

	fmt.Println("Available configuration profiles:")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	for _, file := range files {
		base := filepath.Base(file)
		fmt.Printf("  • %s\n", strings.TrimSuffix(base, ".yaml"))
	}
	return nil
}

func runConfigureSet(cmd *cobra.Command, args []string) error {
	key := strings.TrimSpace(args[0])
	rawVal := args[1]
	profile := viper.GetString("configure.profile")

	cfg, cfgPath, err := loadConfigFile(profile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	val := parseValueForKey(key, rawVal)
	setNested(cfg, strings.Split(key, "."), val)

	if err := writeYAMLFile(cfgPath, cfg); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	logrus.Infof("Set %s = %v in profile %s", key, val, profile)
	return nil
}

func runConfigureGet(cmd *cobra.Command, args []string) error {
	key := strings.TrimSpace(args[0])
	profile := viper.GetString("configure.profile")

	if err := loadProfileIntoViper(profile); err != nil {
		return fmt.Errorf("failed to load profile %s: %w", profile, err)
	}

	val := viper.Get(key)
	if val == nil {
		fmt.Printf("%s = <nil>\n", key)
		return nil
	}
	fmt.Printf("%s = %v\n", key, val)
	return nil
}

func loadProfileIntoViper(profile string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	cfg := filepath.Join(home, ".sublynx", profile+".yaml")
	if _, err := os.Stat(cfg); os.IsNotExist(err) {
		return fmt.Errorf("profile %s does not exist", profile)
	}
	viper.SetConfigFile(cfg)
	return viper.ReadInConfig()
}

func loadConfigFile(profile string) (map[string]interface{}, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	configDir := filepath.Join(home, ".sublynx")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return nil, "", fmt.Errorf("failed to create config directory: %w", err)
	}
	configFile := filepath.Join(configDir, profile+".yaml")

	cfg := map[string]interface{}{}
	if _, err := os.Stat(configFile); err == nil {
		b, rerr := os.ReadFile(configFile)
		if rerr != nil {
			return nil, "", fmt.Errorf("failed to read configuration: %w", rerr)
		}
		if uerr := yaml.Unmarshal(b, &cfg); uerr != nil {
			return nil, "", fmt.Errorf("failed to parse YAML: %w", uerr)
		}
	}
	return cfg, configFile, nil
}

func writeYAMLFile(path string, v interface{}) error {
	out, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func setNested(dst map[string]interface{}, keys []string, val interface{}) {
	if len(keys) == 0 {
		return
	}
	if len(keys) == 1 {
		dst[keys[0]] = val
		return
	}
	k := keys[0]
	child, ok := dst[k].(map[string]interface{})
	if !ok {
		child = map[string]interface{}{}
	}
	setNested(child, keys[1:], val)
	dst[k] = child
}

func parseValueForKey(key, s string) interface{} {
	trim := strings.TrimSpace(s)

	if strings.Contains(trim, ",") {
		parts := strings.Split(trim, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				out = append(out, t)
			}
		}
		return out
	}

	if b, err := strconv.ParseBool(trim); err == nil {
		return b
	}

	if i, err := strconv.Atoi(trim); err == nil {
		return i
	}

	if f, err := strconv.ParseFloat(trim, 64); err == nil {
		return f
	}

	if containsAny(strings.ToLower(key), []string{"timeout", "interval", "retention", "delay"}) {
		if d, err := time.ParseDuration(trim); err == nil {
			return d.String()
		}
	}
	return trim
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func getDefaultConfig() map[string]interface{} {
	return map[string]interface{}{
		"log_level":            "info",
		"log_format":           "json",
		"max_concurrent_scans": 5,
		"default_timeout":      "30m",
		"output_directory":     "./reports",
		"data_directory":       "./data",
		"temp_directory":       "/tmp/sublynx",
		"rate_limit":           10,
		"retry_attempts":       3,
		"scan": map[string]interface{}{
			"methods":        []string{"all"},
			"validation":     []string{"all"},
			"depth":          2,
			"stealth":        false,
			"config_profile": "default",
		},
	}
}

func confirmOverwrite() (bool, error) {
	fmt.Print("Configuration file already exists. Overwrite? (y/N): ")
	reader := bufio.NewReader(os.Stdin)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	resp = strings.TrimSpace(resp)
	return resp == "y" || resp == "Y", nil
}
