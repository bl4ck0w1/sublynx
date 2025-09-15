package commands

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/bl4ck0w1/sublynx/internal/orchestration"
)

func NewStatsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show runtime statistics",
		Long:  `Show runtime statistics about SubLynx including active scans and resource usage.`,
		RunE:  runStats,
	}
}

func runStats(cmd *cobra.Command, args []string) error {
	scanner, err := createScanner()
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}
	// defer scanner.Close()

	stats := scanner.GetStats()
	getInt := func(k string) int {
		if v, ok := stats[k]; ok {
			switch x := v.(type) {
			case int:
				return x
			case int64:
				return int(x)
			case float64:
				return int(x)
			}
		}
		return 0
	}
	getString := func(k string) string {
		if v, ok := stats[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	getFloat := func(k string) float64 {
		if v, ok := stats[k]; ok {
			if f, ok := v.(float64); ok {
				return f
			}
		}
		return 0
	}

	fmt.Println("Runtime Statistics:")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	fmt.Printf("Active Scans: %d\n", getInt("active_scans"))
	fmt.Printf("Max Concurrent: %d\n", getInt("max_concurrent"))
	fmt.Printf("Default Timeout: %s\n", getString("default_timeout"))
	fmt.Printf("Retry Attempts: %d\n", getInt("retry_attempts"))
	fmt.Printf("Rate Limit: %d requests/second\n", getInt("rate_limit"))

	if v, ok := stats["active_scan_details"]; ok && v != nil {
		if list, ok := v.([]map[string]interface{}); ok {
			if len(list) > 0 {
				fmt.Println("\nActive Scans Details:")
				for i, scan := range list {
					sid, _ := scan["scan_id"].(string)
					domain, _ := scan["domain"].(string)
					var prog float64
					if p, ok := scan["progress"].(float64); ok {
						prog = p
					}
					fmt.Printf("  %d. %s - %s (%.1f%%)\n", i+1, sid, domain, prog)
				}
			}
		}
	}

	return nil
}


var _ = orchestration.Scanner{}