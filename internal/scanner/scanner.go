// Package scanner provides scanning the target file
package scanner

import (
	"fmt"
	"os"
)

type Scanner interface {
	Scan(string) ([]string, error)
	Analyze() error
}

type VulnScanner struct{}

func New() *VulnScanner {
	return &VulnScanner{}
}

func (vs *VulnScanner) Scan(projectPath string) ([]string, error) {
	var dependencies []string

	files := []string{
		"go.mod",           // Go
		"package.json",     // Node.js
		"pom.xml",          // Maven
		"requirements.txt", // Python
		"Cargo.toml",       // Rust
	}

	for _, file := range files {
		filepath := fmt.Sprintf("%s/%s", projectPath, file)
		if _, err := os.Stat(filepath); err == nil {
			deps, err := os.ReadFile(filepath)
			if err != nil {
				return nil, err
			}
			dependencies = append(dependencies, string(deps))
		}
	}
	return dependencies, nil
}
