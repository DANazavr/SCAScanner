// Package scanner provides scanning the target file
package scanner

import (
	"SCAScanner/internal/models"
	"SCAScanner/pkg/parsers"
	"fmt"
)

type Scanner interface {
	Scan(string) ([]models.Dependency, error)
	Analyze() error
}

type VulnScanner struct{}

func New() *VulnScanner {
	return &VulnScanner{}
}

func (vs *VulnScanner) Scan(projectPath string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	files := []string{
		"go.mod",           // Go
		"package.json",     // Node.js
		"pom.xml",          // Maven
		"requirements.txt", // Python
		"Cargo.toml",       // Rust
	}

	for _, file := range files {
		var err error
		filepath := fmt.Sprintf("%s\\%s", projectPath, file)
		switch file {
		case "go.mod":
			dependencies, err = parsers.ParseGoMod(filepath)
			if err != nil {
				return nil, err
			}
		default:
			continue
		}
	}
	return dependencies, nil
}

func (vs *VulnScanner) Analyze() error {
	return nil
}
