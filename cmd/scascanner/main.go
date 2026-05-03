package main

import (
	"SCAScanner/config"
	"SCAScanner/internal/models"
	"SCAScanner/internal/reporters"
	"SCAScanner/internal/scanner"
	"SCAScanner/pkg/cache"
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
	language    string
	redisAddr   string
	configPath  string
	saveConfig  bool
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
	rootCmd.Flags().StringVarP(&redisAddr, "redis-addr", "r", "", "Redis address for caching (overrides config)")
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to configuration file (default: ~/.scascanner/config.json)")
	rootCmd.Flags().BoolVar(&saveConfig, "save-config", false, "Save current configuration to default location")
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func rootExecuteble(projectPath string) {
	fmt.Printf("Scanning project at path: %s\n", projectPath)

	// Load configuration
	var cfg *config.Config
	if configPath != "" {
		// Load from specified path
		var err error
		cfg, err = config.LoadFromFile(configPath)
		if err != nil {
			log.Fatalf("Error loading config from %s: %v", configPath, err)
		}
	} else {
		// Load from default locations
		cfg = config.Load()
	}

	// Apply command-line overrides
	override := config.Override{
		RedisAddr: redisAddr,
	}
	cfg.ApplyOverride(override)

	// Save config if requested
	if saveConfig {
		if err := cfg.Save(config.GetConfigPath()); err != nil {
			log.Printf("Warning: Failed to save config: %v", err)
		}
		fmt.Println("Configuration saved successfully")
		return
	}

	// Parse cache TTL
	ttl, err := time.ParseDuration(cfg.Cache.TTL)
	if err != nil {
		log.Printf("Warning: Invalid cache TTL %s, using default 24h: %v", cfg.Cache.TTL, err)
		ttl = 24 * time.Hour
	}

	// Initialize cache based on config
	var cacheInstance cache.Cache
	if cfg.Cache.EnableRedis && cfg.Redis.Enabled {
		cacheInstance = cache.NewMultiLevelCache(
			cfg.Redis.Address,
			cfg.Redis.Password,
			cfg.Redis.DB,
			ttl,
		)
	} else if cfg.Cache.EnableLocal {
		cacheInstance = cache.NewLocalCache()
	}

	if cacheInstance == nil {
		log.Printf("Warning: Cache disabled, CVE lookups will be slower")
	}

	defer func() {
		if cacheInstance != nil {
			_ = cacheInstance.Close()
		}
	}()

	s := scanner.New()
	if cacheInstance != nil {
		s.SetCache(cacheInstance)
	}

	deps, err := s.Scan(projectPath, language)
	if err != nil {
		log.Fatalf("Error during scanning: %v", err)
	}

	fmt.Printf("Found %d dependencies\n", len(deps))
	for _, dep := range deps {
		fmt.Printf("  - %s @ %s\n", dep.Name, dep.Version)
	}

	vulnerabilities, err := searchVulnerabilities(s, deps)
	if err != nil {
		log.Fatalf("Error searching vulnerabilities: %v", err)
	}

	fmt.Printf("Found %d vulnerabilities\n", len(vulnerabilities))

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
				vuln, err := s.SearchCVE(dep.Name, dep.Version, dep.Ecosystem)
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
