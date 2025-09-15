package commands

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/bl4ck0w1/sublynx/pkg/models"
	"github.com/bl4ck0w1/sublynx/pkg/utils"
)

func NewOutputCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "output",
		Short: "Manage output and reports",
		Long: `Manage scan output and reports, including generating reports
in different formats and viewing report statistics.`,
	}
	cmd.AddCommand(newOutputGenerateCommand())
	cmd.AddCommand(newOutputListCommand())
	cmd.AddCommand(newOutputViewCommand())
	cmd.AddCommand(newOutputCleanupCommand())
	cmd.AddCommand(newOutputStatsCommand())

	return cmd
}


func newOutputGenerateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate <scan-id>",
		Short: "Generate reports for a scan",
		Long:  `Generate reports in specified formats for a completed scan.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runOutputGenerate,
	}

	cmd.Flags().StringSliceP("formats", "f", []string{"txt", "csv", "json"}, "Output formats (txt,csv,json)")
	cmd.Flags().StringP("output", "o", "", "Output directory (defaults to output_directory in config)")
	cmd.Flags().Bool("raw", false, "Include raw data in JSON reports")
	cmd.Flags().Bool("compress", true, "Compress output files with gzip (.gz)")
	_ = viper.BindPFlag("output.formats", cmd.Flags().Lookup("formats"))
	_ = viper.BindPFlag("output.directory", cmd.Flags().Lookup("output"))
	_ = viper.BindPFlag("output.include_raw", cmd.Flags().Lookup("raw"))
	_ = viper.BindPFlag("output.compress", cmd.Flags().Lookup("compress"))

	return cmd
}

func newOutputListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available reports",
		Long:  `List all available scan reports.`,
		RunE:  runOutputList,
	}
}

func newOutputViewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "view <scan-id>",
		Short: "View a specific report",
		Long:  `View a specific scan report in the terminal.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runOutputView,
	}

	cmd.Flags().StringP("format", "f", "txt", "Report format to view (txt,csv,json)")
	_ = viper.BindPFlag("output.format", cmd.Flags().Lookup("format"))

	return cmd
}

func newOutputCleanupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Clean up old reports",
		Long:  `Clean up reports older than the specified retention period.`,
		RunE:  runOutputCleanup,
	}

	cmd.Flags().StringP("older-than", "o", "720h", "Delete reports older than this duration (e.g., 720h, 30d)")
	cmd.Flags().Bool("dry-run", false, "Dry run (show what would be deleted)")
	_ = viper.BindPFlag("output.older_than", cmd.Flags().Lookup("older-than"))
	_ = viper.BindPFlag("output.dry_run", cmd.Flags().Lookup("dry-run"))

	return cmd
}

func newOutputStatsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show output statistics",
		Long:  `Show statistics about stored reports and output files.`,
		RunE:  runOutputStats,
	}
}

func runOutputGenerate(cmd *cobra.Command, args []string) error {
	scanID := args[0]
	logrus.Infof("Generating reports for scan: %s", scanID)

	results, err := loadScanResults(scanID)
	if err != nil {
		return fmt.Errorf("failed to load scan results: %w", err)
	}

	outputDir := viper.GetString("output.directory")
	if outputDir == "" {
		outputDir = viper.GetString("output_directory")
		if outputDir == "" {
			outputDir = "./reports"
		}
	}
	if err := utils.EnsureDir(outputDir); err != nil {
		return fmt.Errorf("failed to prepare output directory: %w", err)
	}

	formats := viper.GetStringSlice("output.formats")
	includeRaw := viper.GetBool("output.include_raw")
	compress := viper.GetBool("output.compress")

	for _, format := range formats {
		format = strings.ToLower(strings.TrimSpace(format))
		if format == "" {
			continue
		}
		fp, err := generateReportFile(outputDir, results, format, includeRaw, compress)
		if err != nil {
			logrus.Warnf("Failed to generate %s report: %v", format, err)
			continue
		}
		logrus.Infof("Generated %s report: %s", format, fp)
	}

	logrus.Info("Report generation completed")
	return nil
}

func runOutputList(cmd *cobra.Command, args []string) error {
	outputDir := viper.GetString("output_directory")
	if v := viper.GetString("output.directory"); v != "" {
		outputDir = v
	}
	if outputDir == "" {
		outputDir = "./reports"
	}

	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		logrus.Infof("No reports directory found at %s", outputDir)
		return nil
	}

	reportFiles, err := findReportFiles(outputDir)
	if err != nil {
		return fmt.Errorf("failed to find report files: %w", err)
	}

	if len(reportFiles) == 0 {
		logrus.Info("No reports found")
		return nil
	}

	fmt.Printf("Available reports in %s:\n", outputDir)
	fmt.Println("═══════════════════════════════════════════════════════════════")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SCAN ID\tDOMAIN\tFORMAT\tSIZE\tMODIFIED")

	for _, file := range reportFiles {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			emptyIf(file.ScanID, "-"),
			emptyIf(file.Domain, "-"),
			file.Format,
			utils.HumanizeBytes(file.Size),
			file.Modified.Format("2006-01-02 15:04"),
		)
	}

	_ = w.Flush()
	return nil
}

func runOutputView(cmd *cobra.Command, args []string) error {
	scanID := args[0]
	format := strings.ToLower(strings.TrimSpace(viper.GetString("output.format")))
	if format == "" {
		format = "txt"
	}

	outputDir := viper.GetString("output_directory")
	if v := viper.GetString("output.directory"); v != "" {
		outputDir = v
	}
	if outputDir == "" {
		outputDir = "./reports"
	}

	reportFile, err := findSpecificReport(outputDir, scanID, format)
	if err != nil {
		return fmt.Errorf("failed to find report: %w", err)
	}
	if reportFile == "" {
		return fmt.Errorf("no report found for scan %s in format %s", scanID, format)
	}

	var reader io.ReadCloser
	f, err := os.Open(reportFile)
	if err != nil {
		return fmt.Errorf("failed to open report: %w", err)
	}
	defer f.Close()

	if strings.HasSuffix(reportFile, ".gz") {
		gr, gzErr := gzip.NewReader(f)
		if gzErr != nil {
			return fmt.Errorf("failed to read gzip report: %w", gzErr)
		}
		defer gr.Close()
		reader = gr
	} else {
		reader = f
	}

	_, err = io.Copy(os.Stdout, reader)
	return err
}

func runOutputCleanup(cmd *cobra.Command, args []string) error {
	outputDir := viper.GetString("output_directory")
	if v := viper.GetString("output.directory"); v != "" {
		outputDir = v
	}
	if outputDir == "" {
		outputDir = "./reports"
	}

	olderThan := viper.GetString("output.older_than")
	dryRun := viper.GetBool("output.dry_run")

	duration, err := utils.ParseDurationExtended(olderThan)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	cutoffTime := time.Now().Add(-duration)

	logrus.Infof("Cleaning up reports older than %s (before %s)", olderThan, cutoffTime.Format(time.RFC3339))
	if dryRun {
		logrus.Info("Dry run enabled - no files will be deleted")
	}

	files, err := findOldReportFiles(outputDir, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to find old reports: %w", err)
	}

	if len(files) == 0 {
		logrus.Info("No old reports found")
		return nil
	}

	deletedCount := 0
	var totalSize int64

	for _, file := range files {
		if dryRun {
			logrus.Infof("Would delete: %s (%s, modified %s)",
				file.Path, utils.HumanizeBytes(file.Size), file.Modified.Format("2006-01-02"))
			continue
		}
		if err := os.Remove(file.Path); err != nil {
			logrus.Warnf("Failed to delete %s: %v", file.Path, err)
		} else {
			logrus.Infof("Deleted: %s", file.Path)
			deletedCount++
			totalSize += file.Size
		}
	}

	if dryRun {
		logrus.Infof("Would delete %d files (%s total)", len(files), utils.HumanizeBytes(totalSize))
	} else {
		logrus.Infof("Deleted %d files (%s freed)", deletedCount, utils.HumanizeBytes(totalSize))
	}

	return nil
}

func runOutputStats(cmd *cobra.Command, args []string) error {
	outputDir := viper.GetString("output_directory")
	if v := viper.GetString("output.directory"); v != "" {
		outputDir = v
	}
	if outputDir == "" {
		outputDir = "./reports"
	}

	stats, err := getOutputStatistics(outputDir)
	if err != nil {
		return fmt.Errorf("failed to get output statistics: %w", err)
	}

	fmt.Println("Output Statistics:")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Total Reports:\t%d\n", stats.TotalReports)
	fmt.Fprintf(w, "Total Size:\t%s\n", utils.HumanizeBytes(stats.TotalSize))
	if !stats.OldestReport.IsZero() {
		fmt.Fprintf(w, "Oldest Report:\t%s\n", stats.OldestReport.Format("2006-01-02"))
	}
	if !stats.NewestReport.IsZero() {
		fmt.Fprintf(w, "Newest Report:\t%s\n", stats.NewestReport.Format("2006-01-02"))
	}
	fmt.Fprintf(w, "Average Report Size:\t%s\n", utils.HumanizeBytes(stats.AverageSize))

	fmt.Fprintln(w, "\nReports by Format:")
	for format, count := range stats.ReportsByFormat {
		fmt.Fprintf(w, "  %s:\t%d\n", format, count)
	}

	fmt.Fprintln(w, "\nReports by Domain:")
	for domain, count := range stats.ReportsByDomain {
		fmt.Fprintf(w, "  %s:\t%d\n", domain, count)
	}

	_ = w.Flush()
	return nil
}

func loadScanResults(scanID string) (*models.ScanResult, error) {
	dataDir := viper.GetString("data_directory")
	if dataDir == "" {
		dataDir = "./data"
	}

	base := filepath.Join(dataDir, "results", scanID)
	candidates := []string{}
	_ = filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			candidates = append(candidates, p)
		}
		return nil
	})

	if len(candidates) == 0 {
		_ = filepath.WalkDir(dataDir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(d.Name()), ".json") && strings.Contains(p, scanID) {
				candidates = append(candidates, p)
			}
			return nil
		})
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no result JSON found for scan %s under %s", scanID, dataDir)
	}

	var chosen string
	var chosenInfo os.FileInfo
	for _, c := range candidates {
		fi, err := os.Stat(c)
		if err != nil {
			continue
		}
		if chosen == "" || fi.ModTime().After(chosenInfo.ModTime()) {
			chosen = c
			chosenInfo = fi
		}
	}

	if chosen == "" {
		return nil, fmt.Errorf("no readable result JSON found for scan %s", scanID)
	}

	raw, err := os.ReadFile(chosen)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", chosen, err)
	}

	var res models.ScanResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("unmarshal results: %w", err)
	}
	return &res, nil
}

func generateReportFile(dir string, results *models.ScanResult, format string, includeRaw, compress bool) (string, error) {
	filename := fmt.Sprintf("sublynx_%s_summary_%s.%s",
		safeFilePart(results.TargetDomain),
		results.EndTime.Format("20060102_150405"),
		format,
	)
	fp := filepath.Join(dir, filename)

	switch format {
	case "txt":
		content := buildTXTReport(results)
		if err := writeMaybeGzip(fp, []byte(content), compress); err != nil {
			return "", err
		}
		if compress {
			fp += ".gz"
		}
		return fp, nil

	case "csv":
		var b strings.Builder
		w := csv.NewWriter(&b)
		_ = w.Write([]string{"# ScanID", results.ScanID})
		_ = w.Write([]string{"# Domain", results.TargetDomain})
		_ = w.Write([]string{"# StartTime", results.StartTime.Format(time.RFC3339)})
		_ = w.Write([]string{"# EndTime", results.EndTime.Format(time.RFC3339)})
		_ = w.Write([]string{})
		_ = w.Write([]string{"Subdomain", "Status", "RiskScore", "OpenPorts"})

		for _, s := range results.Subdomains {
			openPorts := []string{}
			for _, p := range s.Ports {
				if p.Status == "open" {
					openPorts = append(openPorts, fmt.Sprintf("%d/%s", p.Number, p.Protocol))
				}
			}
			_ = w.Write([]string{
				s.Name, s.Status, fmt.Sprintf("%.2f", s.RiskScore), strings.Join(openPorts, ";"),
			})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return "", err
		}
		if err := writeMaybeGzip(fp, []byte(b.String()), compress); err != nil {
			return "", err
		}
		if compress {
			fp += ".gz"
		}
		return fp, nil

	case "json":
		var out any
		if includeRaw {
			out = results
		} else {
			out = map[string]any{
				"scan_id":       results.ScanID,
				"target_domain": results.TargetDomain,
				"start_time":    results.StartTime,
				"end_time":      results.EndTime,
				"stats":         results.Stats,
				"findings":      results.Findings,
				"subdomains":    results.Subdomains,
			}
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return "", err
		}
		if err := writeMaybeGzip(fp, b, compress); err != nil {
			return "", err
		}
		if compress {
			fp += ".gz"
		}
		return fp, nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

func buildTXTReport(r *models.ScanResult) string {
	activePct := 0.0
	if r.Stats.TotalSubdomains > 0 {
		activePct = (float64(r.Stats.ActiveSubdomains) / float64(r.Stats.TotalSubdomains)) * 100
	}
	duration := r.EndTime.Sub(r.StartTime).Round(time.Second)

	var b strings.Builder
	fmt.Fprintf(&b, "ScanID: %s\n", r.ScanID)
	fmt.Fprintf(&b, "Domain: %s\n", r.TargetDomain)
	fmt.Fprintf(&b, "Start:  %s\n", r.StartTime.Format(time.RFC3339))
	fmt.Fprintf(&b, "End:    %s\n", r.EndTime.Format(time.RFC3339))
	fmt.Fprintf(&b, "Duration: %v\n", duration)
	fmt.Fprintln(&b, "================================================================")
	fmt.Fprintf(&b, "Subdomains Found: %d (%.0f%% active)\n", r.Stats.TotalSubdomains, activePct)
	fmt.Fprintf(&b, "Findings: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
		r.Stats.TotalFindings, r.Stats.CriticalFindings, r.Stats.HighRiskFindings, r.Stats.MediumRiskFindings, r.Stats.LowRiskFindings)
	fmt.Fprintf(&b, "Risk Score: %.2f/10.00\n", r.Stats.RiskScore)
	fmt.Fprintln(&b, "================================================================")
	fmt.Fprintln(&b, "Top Findings:")
	if len(r.Findings) == 0 {
		fmt.Fprintln(&b, "  - None")
	} else {
		for i, f := range r.Findings {
			if i >= 10 {
				fmt.Fprintln(&b, "  ...")
				break
			}
			fmt.Fprintf(&b, "  - [%s] %s (confidence %.2f) target=%s\n", strings.ToUpper(f.Severity), f.Title, f.Confidence, f.Target)
		}
	}
	return b.String()
}

func writeMaybeGzip(path string, data []byte, compress bool) error {
	if !compress {
		return utils.SafeWriteFile(path, data, 0o644)
	}
	gzPath := path + ".gz"
	tmp := gzPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	gzw := gzip.NewWriter(f)
	gzw.Name = filepath.Base(path)
	_, werr := gzw.Write(data)
	cerr := gzw.Close()
	cferr := f.Close()
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(tmp)
		return cerr
	}
	if cferr != nil {
		_ = os.Remove(tmp)
		return cferr
	}
	return os.Rename(tmp, gzPath)
}

func findReportFiles(outputDir string) ([]ReportFile, error) {
	var files []ReportFile
	err := filepath.WalkDir(outputDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		lname := strings.ToLower(d.Name())
		if !(strings.HasSuffix(lname, ".txt") ||
			strings.HasSuffix(lname, ".csv") ||
			strings.HasSuffix(lname, ".json") ||
			strings.HasSuffix(lname, ".txt.gz") ||
			strings.HasSuffix(lname, ".csv.gz") ||
			strings.HasSuffix(lname, ".json.gz")) {
			return nil
		}
		fi, statErr := os.Stat(path)
		if statErr != nil {
			return nil
		}
		scanID, domain := extractIDsFromReport(path)
		format := fileFormatFromName(lname)
		files = append(files, ReportFile{
			Path:     path,
			ScanID:   scanID,
			Domain:   domain,
			Format:   format,
			Size:     fi.Size(),
			Modified: fi.ModTime(),
		})
		return nil
	})
	return files, err
}

func findSpecificReport(outputDir, scanID, format string) (string, error) {
	var candidate string
	err := filepath.WalkDir(outputDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ln := strings.ToLower(d.Name())
		if !(strings.HasSuffix(ln, "."+format) || strings.HasSuffix(ln, "."+format+".gz")) {
			return nil
		}
		if strings.Contains(ln, strings.ToLower(scanID)) {
			candidate = path
			return errors.New("done") 
		}
		sid, _ := extractIDsFromReport(path)
		if sid == scanID {
			candidate = path
			return errors.New("done")
		}
		return nil
	})
	if err != nil && err.Error() != "done" {
		return "", err
	}
	return candidate, nil
}

func findOldReportFiles(outputDir string, cutoff time.Time) ([]ReportFile, error) {
	all, err := findReportFiles(outputDir)
	if err != nil {
		return nil, err
	}
	var old []ReportFile
	for _, f := range all {
		if f.Modified.Before(cutoff) {
			old = append(old, f)
		}
	}
	return old, nil
}

func getOutputStatistics(outputDir string) (*OutputStatistics, error) {
	all, err := findReportFiles(outputDir)
	if err != nil {
		return nil, err
	}
	stats := &OutputStatistics{
		ReportsByFormat: map[string]int{},
		ReportsByDomain: map[string]int{},
	}
	if len(all) == 0 {
		return stats, nil
	}

	var totalSize int64
	var oldest, newest time.Time

	for i, f := range all {
		totalSize += f.Size
		stats.ReportsByFormat[f.Format]++
		if f.Domain != "" {
			stats.ReportsByDomain[f.Domain]++
		}
		if i == 0 || f.Modified.Before(oldest) {
			oldest = f.Modified
		}
		if i == 0 || f.Modified.After(newest) {
			newest = f.Modified
		}
	}
	stats.TotalReports = len(all)
	stats.TotalSize = totalSize
	if len(all) > 0 {
		stats.AverageSize = totalSize / int64(len(all))
	}
	stats.OldestReport = oldest
	stats.NewestReport = newest
	return stats, nil
}

func extractIDsFromReport(path string) (scanID, domain string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gr, gzErr := gzip.NewReader(f)
		if gzErr != nil {
			return "", ""
		}
		defer gr.Close()
		r = gr
	}

	br := bufio.NewReader(r)
	buf, _ := br.Peek(8192)

	s := string(buf)
	if strings.Contains(s, "\"scan_id\"") {
		var tmp struct {
			ScanID       string `json:"scan_id"`
			TargetDomain string `json:"target_domain"`
		}
		dec := json.NewDecoder(strings.NewReader(s))
		_ = dec.Decode(&tmp)
		if tmp.ScanID != "" || tmp.TargetDomain != "" {
			return tmp.ScanID, tmp.TargetDomain
		}
	}

	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "scanid:") {
			scanID = strings.TrimSpace(strings.TrimPrefix(line, "ScanID:"))
		} else if strings.HasPrefix(strings.ToLower(line), "domain:") {
			domain = strings.TrimSpace(strings.TrimPrefix(line, "Domain:"))
		} else if strings.HasPrefix(line, "# ScanID") {
			parts := strings.SplitN(line, ",", 2)
			if len(parts) == 2 {
				scanID = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "# Domain") {
			parts := strings.SplitN(line, ",", 2)
			if len(parts) == 2 {
				domain = strings.TrimSpace(parts[1])
			}
		}
		if scanID != "" && domain != "" {
			break
		}
	}
	return scanID, domain
}

func fileFormatFromName(lowerName string) string {
	switch {
	case strings.HasSuffix(lowerName, ".txt"), strings.HasSuffix(lowerName, ".txt.gz"):
		return "txt"
	case strings.HasSuffix(lowerName, ".csv"), strings.HasSuffix(lowerName, ".csv.gz"):
		return "csv"
	case strings.HasSuffix(lowerName, ".json"), strings.HasSuffix(lowerName, ".json.gz"):
		return "json"
	default:
		return "unknown"
	}
}

func safeFilePart(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

func emptyIf(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

type ReportFile struct {
	Path     string
	ScanID   string
	Domain   string
	Format   string
	Size     int64
	Modified time.Time
}

type OutputStatistics struct {
	TotalReports    int
	TotalSize       int64
	OldestReport    time.Time
	NewestReport    time.Time
	AverageSize     int64
	ReportsByFormat map[string]int
	ReportsByDomain map[string]int
}
