package main

import (
	"SCAScanner/internal/models"
	"SCAScanner/internal/scanner"
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
)

var (
	projectPath string
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
	fmt.Println("Dependencies found:")
	for _, dep := range deps {
		fmt.Println(dep)
	}
	var vulnerabilities []models.Vulnerability
	for _, v := range deps {
		vuln, err := s.SearchCVE(v.Name)
		if err != nil {
			log.Printf("Error searching CVE for %s: %v", v.Name, err)
			continue
		}
		vulnerabilities = append(vulnerabilities, vuln...)

		time.Sleep(6 * time.Second)
	}
	fmt.Println("Vulnerabilities found:")
	for _, vuln := range vulnerabilities {
		fmt.Printf("CVE ID: %s\nDescription: %s\nSeverity: %s\nAffected Package: %s\nCVSS Score: %.1f\n\n",
			vuln.CVEID, vuln.Description, vuln.Severity, vuln.AffectedPackage, vuln.CVSSScore)
	}
}
