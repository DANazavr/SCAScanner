// Package scanner provides scanning the target file
package scanner

import (
	"SCAScanner/internal/models"
	"SCAScanner/pkg/parsers"
	"io/fs"
	"os"
	"path/filepath"
)

type Scanner interface {
	Scan(string, string) ([]models.Dependency, error)
	Analyze() error
}

type VulnScanner struct{}

func New() *VulnScanner {
	return &VulnScanner{}
}

func (vs *VulnScanner) Scan(projectPath string, language string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	allFiles := map[string]func(string) ([]models.Dependency, error){
		"go.mod":           parsers.ParseGoMod,
		"package.json":     parsers.ParsePackageJSON,
		"pom.xml":          parsers.ParsePomXML,
		"requirements.txt": parsers.ParseRequirementsTxt,
		"Сargo.toml":       parsers.ParseCargoToml,
	}

	// Language to file mappings
	languageMap := map[string][]string{
		"go":     {"go.mod"},
		"node":   {"package.json"},
		"java":   {"pom.xml"},
		"python": {"requirements.txt"},
		"rust":   {"Сargo.toml"},
		"all":    {"go.mod", "package.json", "pom.xml", "requirements.txt", "Сargo.toml"},
	}

	// Get files to scan based on language
	var filesToScan []string
	if langs, ok := languageMap[language]; ok {
		filesToScan = langs
	} else {
		filesToScan = languageMap["all"]
	}

	// Filter files map
	files := make(map[string]func(string) ([]models.Dependency, error))
	for _, filename := range filesToScan {
		if parser, ok := allFiles[filename]; ok {
			files[filename] = parser
		}
	}

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		filename := d.Name()
		if parser, ok := files[filename]; ok {
			deps, err := parser(path)
			if err != nil {
				if os.IsNotExist(err) {
					return nil // Игнорируем ошибку, если файл не найден
				}
				return err
			}
			dependencies = append(dependencies, deps...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dependencies, nil
}

func (vs *VulnScanner) Analyze() error {
	return nil
}
