package main

import (
	"SCAScanner/internal/models"
	"SCAScanner/internal/reporters"
	"SCAScanner/internal/scanner"
	"fmt"
	"log"
	"time"

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
	rootCmd.Flags().StringVarP(&format, "format", "f", "html", "format of the report (html or json)")
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
	var vulnerabilities []models.Vulnerability
	for _, v := range deps {
		vuln, err := s.SearchCVE(v.Name, v.Version)
		if err != nil {
			log.Printf("Error searching CVE for %s: %v", v.Name, err)
			continue
		}
		vulnerabilities = append(vulnerabilities, vuln...)

		time.Sleep(6 * time.Second)
	}

	if format == "json" {
		if err := reporters.GenerateJSONReport(deps, vulnerabilities, outputPath); err != nil {
			log.Fatalf("Error generating report: %v", err)
		}
		fmt.Printf("Report generated successfully at: %s/report.json\n", outputPath)
	}

	if format == "html" {
		if err := reporters.GenerateHTMLReport(deps, vulnerabilities, outputPath); err != nil {
			log.Fatalf("Error generating HTML report: %v", err)
		}
		fmt.Printf("Report generated successfully at: %s/report.html\n", outputPath)
	}
}
