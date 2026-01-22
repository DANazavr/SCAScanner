package main

import (
	"SCAScanner/internal/scanner"
	"fmt"
	"log"

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
	scanener := scanner.New()
	deps, err := scanener.Scan(projectPath)
	if err != nil {
		log.Fatalf("Error during scanning: %v", err)
	}
	fmt.Println("Dependencies found:")
	for _, dep := range deps {
		fmt.Println(dep)
	}
}
