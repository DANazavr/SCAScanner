package main

import (
	"SCAScanner/internal/models"
	"SCAScanner/internal/reporters"
	"SCAScanner/internal/scanner"
	"fmt"
	"log"
	"sync"
	"time"

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

	vulnerabilities, err := searchVulnerabilities(s, deps)
	if err != nil {
		log.Fatalf("Error searching vulnerabilities: %v", err)
	}

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

func searchVulnerabilities(s *scanner.VulnScanner, deps []models.Dependency) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	var mu sync.Mutex

	workerCount := 5
	jobs := make(chan models.Dependency, len(deps))

	bar := progressbar.NewOptions(len(deps),
		progressbar.OptionSetDescription("Searching CVEs..."),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(15),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionClearOnFinish(),
	)

	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for dep := range jobs {
				vuln, err := s.SearchCVE(dep.Name, dep.Version)
				if err != nil {
					log.Printf("Error searching CVE for %s: %v", dep.Name, err)
				} else {
					mu.Lock()
					vulnerabilities = append(vulnerabilities, vuln...)
					mu.Unlock()
				}

				bar.Add(1)
			}
		}()
	}

	for _, d := range deps {
		jobs <- d
	}
	close(jobs)

	wg.Wait()

	bar.Finish()

	return vulnerabilities, nil
}
