package main

import (
	"SCAScanner/internal/models"
	"SCAScanner/internal/reporters"
	"SCAScanner/internal/scanner"
	"SCAScanner/pkg/cache"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	projectPath string
	outputPath  string
	format      string
	language    string
	redisAddr   string
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
	rootCmd.Flags().StringVarP(&language, "language", "l", "all", "Programming language to scan (go, node, java, python, rust, or all)")
	rootCmd.Flags().StringVarP(&redisAddr, "redis-addr", "r", getRedisAddr(), "Redis address for caching (format: host:port)")
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func rootExecuteble(projectPath string) {
	fmt.Printf("Scanning project at path: %s\n", projectPath)

	// Initialize cache (Redis + LocalCache with 24h TTL)
	cacheInstance := cache.NewMultiLevelCache(redisAddr, "", 0, 24*time.Hour)
	defer cacheInstance.Close()

	s := scanner.New()
	s.SetCache(cacheInstance)

	deps, err := s.Scan(projectPath, language)
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

func getRedisAddr() string {
	// Check environment variable first
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		return addr
	}
	// Default to localhost:6379
	return "localhost:6379"
}

func searchVulnerabilities(s *scanner.VulnScanner, deps []models.Dependency) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	var mu sync.Mutex

	// Reduced to 1 worker since rate limiting is now handled per-request
	workerCount := 1
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
					bar.Add(1)
					continue
				}
				if vuln != nil && len(vuln[:]) > 0 {
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
