package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/bl4ck0w1/sublynx/internal/orchestration"
	"github.com/bl4ck0w1/sublynx/pkg/models"
	"github.com/bl4ck0w1/sublynx/pkg/utils"
)

func NewScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [domain]",
		Short: "Perform subdomain discovery and analysis",
		Long: `Perform comprehensive subdomain discovery, validation, and security analysis
for a target domain using multiple discovery methods and advanced validation techniques.`,
		Args: cobra.ExactArgs(1),
		RunE: runScan,
	}

	cmd.Flags().StringSliceP("methods", "m", []string{"all"}, "Discovery methods to use (all, ct, passive, permutations, ai)")
	cmd.Flags().StringSliceP("validation", "v", []string{"all"}, "Validation methods to use (all, dns, http, security)")
	cmd.Flags().IntP("depth", "d", 2, "Permutation depth")
	cmd.Flags().IntP("timeout", "t", 30, "Scan timeout in minutes")
	cmd.Flags().Bool("stealth", false, "Enable stealth mode (slower but less detectable)")
	cmd.Flags().Bool("no-validation", false, "Skip validation phase")
	cmd.Flags().Bool("no-security", false, "Skip security checks")
	cmd.Flags().StringP("output", "o", "", "Output file path")
	cmd.Flags().StringSliceP("formats", "f", []string{"txt", "csv"}, "Output formats")
	cmd.Flags().StringP("config-profile", "p", "default", "Configuration profile to use")
	cmd.Flags().Bool("demo", false, "Simulate a full scan with sample output and files (for demos)")
	viper.BindPFlag("scan.demo", cmd.Flags().Lookup("demo"))

	viper.BindPFlag("scan.methods", cmd.Flags().Lookup("methods"))
	viper.BindPFlag("scan.validation", cmd.Flags().Lookup("validation"))
	viper.BindPFlag("scan.depth", cmd.Flags().Lookup("depth"))
	viper.BindPFlag("scan.timeout", cmd.Flags().Lookup("timeout"))
	viper.BindPFlag("scan.stealth", cmd.Flags().Lookup("stealth"))
	viper.BindPFlag("scan.no_validation", cmd.Flags().Lookup("no-validation"))
	viper.BindPFlag("scan.no_security", cmd.Flags().Lookup("no-security"))
	viper.BindPFlag("scan.output", cmd.Flags().Lookup("output"))
	viper.BindPFlag("scan.formats", cmd.Flags().Lookup("formats"))
	viper.BindPFlag("scan.config_profile", cmd.Flags().Lookup("config-profile"))

	return cmd
}

func runScan(cmd *cobra.Command, args []string) error {
	targetDomain := args[0]
	logrus.Infof("Starting scan for domain: %s", targetDomain)

	if !looksLikeDomain(targetDomain) {
		return fmt.Errorf("invalid domain: %s", targetDomain)
	}

	if viper.GetBool("scan.demo") {
		return runDemoScan(targetDomain)
	}

	timeout := time.Duration(viper.GetInt("scan.timeout")) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logrus.Info("Received interrupt signal, shutting down gracefully...")
		cancel()
	}()

	scanner, err := createScanner()
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}

	options := orchestration.ScanOptions{
		DiscoveryMethods:  viper.GetStringSlice("scan.methods"),
		ValidationMethods: viper.GetStringSlice("scan.validation"),
		EvasionTechniques: getEvasionTechniques(),
		Depth:             viper.GetInt("scan.depth"),
		Priority:          1,
	}

	scanID, err := scanner.StartScan(ctx, targetDomain, options)
	if err != nil {
		return fmt.Errorf("failed to start scan: %w", err)
	}
	logrus.Infof("Scan started with ID: %s", scanID)

	return monitorScan(ctx, scanner, scanID, targetDomain)
}

func runDemoScan(domain string) error {
	ts := time.Now().Format("20060102_150405")
	scanID := fmt.Sprintf("scan_%s_%s", domain, ts)
	logrus.Infof("Scan started with ID: %s", scanID)
	printPhaseDone("discovery")
	printPhaseDone("validation")
	printPhaseDone("analysis")
	formats := viper.GetStringSlice("scan.formats")
	if len(formats) == 0 {
		formats = []string{"txt", "csv"}
	}
	outputDir := viper.GetString("output_directory")
	if outputDir == "" {
		outputDir = "./reports"
	}
	_ = os.MkdirAll(outputDir, 0o755)

	for _, f := range formats {
		path := filepath.Join(outputDir, fmt.Sprintf("subnexus_%s_summary_%s.%s", domain, ts, f))
		_ = os.WriteFile(path, demoReportContent(domain, scanID, f), 0o644)
		logrus.Infof("Generated %s report: %s", f, path)
	}
	logrus.Info("Report generation completed")

	fmt.Printf(`
Scan Summary:
═══════════════════════════════════════════════════════════════
Domain:           %s
Subdomains Found: 247 (78%% active)
Security Findings: 14 (Critical: 2, High: 3, Medium: 4)
Risk Score:       6.8/10.0
Scan Duration:    45.2s
═══════════════════════════════════════════════════════════════
`, domain)

	return nil
}

func printPhaseDone(phase string) {
	fmt.Printf("\n[==================================================] %s 100.0%%\n", phase)
}

func demoReportContent(domain, scanID, format string) []byte {
	switch format {
	case "txt":
		return []byte(fmt.Sprintf("SubLynx demo report\nScanID: %s\nDomain: %s\n", scanID, domain))
	case "csv":
		return []byte("field,value\nscan_id," + scanID + "\ndomain," + domain + "\n")
	case "json":
		return []byte(fmt.Sprintf(`{"scan_id":"%s","domain":"%s","demo":true}`, scanID, domain))
	default:
		return []byte(fmt.Sprintf("scan_id=%s domain=%s\n", scanID, domain))
	}
}

func createScanner() (*orchestration.Scanner, error) {
	cfg := orchestration.ScanConfig{
		MaxConcurrentScans: viper.GetInt("max_concurrent_scans"),
		DefaultTimeout:     func() time.Duration { d, _ := time.ParseDuration(viper.GetString("default_timeout")); if d == 0 { d = 30 * time.Minute }; return d }(),
		RetryAttempts:      3,
		RateLimit:          10,
		ValidationDepth:    viper.GetInt("scan.depth"),
	}
	logger := logrus.StandardLogger()
	return orchestration.NewScanner(nil, nil, nil, cfg, logger), nil
}

func getEvasionTechniques() []string {
	techniques := []string{}
	if viper.GetBool("scan.stealth") {
		techniques = append(techniques,
			"proxy_rotation",
			"fingerprint_spoofing",
			"request_masquerading",
			"timing_manipulation",
		)
	}
	return techniques
}

func monitorScan(ctx context.Context, scanner *orchestration.Scanner, scanID, targetDomain string) error {
	displayProgress := func(status string, progress float64) {
		if viper.GetBool("quiet") {
			return
		}
		barWidth := 50
		completed := int(progress * float64(barWidth))
		if completed > barWidth {
			completed = barWidth
		}
		remaining := barWidth - completed
		fmt.Printf("\r[%s%s] %s %.1f%%",
			repeat("=", completed),
			repeat(" ", remaining),
			status,
			progress*100,
		)
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			if ctx.Err() == context.DeadlineExceeded {
				logrus.Warn("Scan timed out")
				return fmt.Errorf("scan timed out after %d minutes", viper.GetInt("scan.timeout"))
			}
			logrus.Info("Scan cancelled by user")
			return nil
		case <-ticker.C:
			status, err := scanner.GetScanStatus(scanID)
			if err != nil {
				fmt.Println()
				return fmt.Errorf("failed to get scan status: %w", err)
			}
			displayProgress(status.Status, status.Progress)
			if status.Progress >= 100 {
				fmt.Println()
				return handleScanCompletion(scanner, scanID, targetDomain)
			}
		}
	}
}

func handleScanCompletion(scanner *orchestration.Scanner, scanID, targetDomain string) error {
	status, err := scanner.GetScanStatus(scanID)
	if err != nil {
		return fmt.Errorf("failed to get scan results: %w", err)
	}
	if status.Results == nil {
		return fmt.Errorf("scan completed but no results available")
	}
	if err := generateReports(status.Results); err != nil {
		return fmt.Errorf("failed to generate reports: %w", err)
	}
	displaySummary(status.Results)
	return nil
}

func generateReports(results *models.ScanResult) error {
	logrus.Info("Generating reports...")
	return nil
}

func displaySummary(results *models.ScanResult) {
	summary := `
Scan Summary:
═══════════════════════════════════════════════════════════════
Domain:           %s
Subdomains Found: %d (%.0f%% active)
Security Findings: %d (Critical: %d, High: %d, Medium: %d)
Risk Score:       %.1f/10.0
Scan Duration:    %v
═══════════════════════════════════════════════════════════════
`
	activePercent := 0.0
	if results.Stats.TotalSubdomains > 0 {
		activePercent = float64(results.Stats.ActiveSubdomains) / float64(results.Stats.TotalSubdomains) * 100
	}
	duration := results.EndTime.Sub(results.StartTime).Round(time.Second)
	fmt.Printf(summary,
		results.TargetDomain,
		results.Stats.TotalSubdomains,
		activePercent,
		results.Stats.TotalFindings,
		results.Stats.CriticalFindings,
		results.Stats.HighRiskFindings,
		results.Stats.MediumRiskFindings,
		results.Stats.RiskScore,
		duration,
	)
}

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func looksLikeDomain(d string) bool {
	if utils.IsValidDomain(d) {
		return true
	}
	re := regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}$`)
	return re.MatchString(d)
}
