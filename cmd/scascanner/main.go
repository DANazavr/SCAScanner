package main

import (
	"SCAScanner/internal/models"
	"SCAScanner/internal/reporters"
	"SCAScanner/internal/scanner"
	"fmt"
	"log"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	projectPath string
	outputPath  string
	format      string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "scascanner",
		Short: "SCA Scanner is a tool for scanning software composition analysis.",
		Run: func(cmd *cobra.Command, args []string) {
			rootExecuteble(projectPath)
		},
	}
	rootCmd.Flags().StringVarP(&projectPath, "path", "p", ".", "Path to the project to scan")
	rootCmd.Flags().StringVarP(&outputPath, "out", "o", ".", "Path to the create report")
	rootCmd.Flags().StringVarP(&format, "format", "f", "", "format of the report (html or json)")
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func rootExecuteble(projectPath string) {
	fmt.Printf("Scanning project at path: %s\n", projectPath)
	s := scanner.New()
	deps, err := s.Scan(projectPath)
	if err != nil {
		log.Fatalf("Error during scanning: %v", err)
	}
	bar := progressbar.NewOptions(len(deps),
		progressbar.OptionSetDescription("Scanning dependencies..."),
		progressbar.OptionShowCount(),
	)
	for range deps {
		bar.Add(1)
	}
	bar = progressbar.NewOptions(len(deps),
		progressbar.OptionSetDescription("Analyzing vulnerabilities..."),
		progressbar.OptionShowCount(),
	)
	var vulnerabilities []models.Vulnerability
	for _, v := range deps {
		vuln, err := s.SearchCVE(v.Name, v.Version)
		if err != nil {
			log.Printf("Error searching CVE for %s: %v", v.Name, err)
			continue
		}
		vulnerabilities = append(vulnerabilities, vuln...)

		bar.Add(1)
		// time.Sleep(6 * time.Second)
	}
	bar.Finish()

	if format == "json" {
		if err := reporters.GenerateJSONReport(deps, vulnerabilities, outputPath); err != nil {
			log.Fatalf("Error generating JSON report: %v", err)
		}
		fmt.Printf("\nReport generated successfully at: %s/report.json\n", outputPath)
	}

	if format == "html" {
		if err := reporters.GenerateHTMLReport(deps, vulnerabilities, outputPath); err != nil {
			log.Fatalf("Error generating HTML report: %v", err)
		}
		fmt.Printf("\nReport generated successfully at: %s/report.html\n", outputPath)
	}

	if format == "" {
		if err := reporters.GenerateHTMLReport(deps, vulnerabilities, outputPath); err != nil {
			log.Fatalf("Error generating HTML report: %v", err)
		}
		if err := reporters.GenerateJSONReport(deps, vulnerabilities, outputPath); err != nil {
			log.Fatalf("Error generating JSON report: %v", err)
		}
		fmt.Printf("\nReports generated successfully at: %s/report.html and %s/report.json\n", outputPath, outputPath)
	}
}
