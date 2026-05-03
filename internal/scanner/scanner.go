package scanner

import (
	"SCAScanner/internal/models"
	"SCAScanner/pkg/cache"
	"SCAScanner/pkg/parsers"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Scanner interface {
	Scan(string, string) ([]models.Dependency, error)
}

type VulnScanner struct {
	cache cache.Cache
}

func New() *VulnScanner {
	return &VulnScanner{}
}

func (vs *VulnScanner) SetCache(c cache.Cache) {
	vs.cache = c
}

func (vs *VulnScanner) Scan(projectPath string, language string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	allFiles := map[string]func(string) ([]models.Dependency, error){
		"go.mod":           parsers.ParseGoMod,
		"package.json":     parsers.ParsePackageJSON,
		"pom.xml":          parsers.ParsePomXML,
		"requirements.txt": parsers.ParseRequirementsTxt,
		"Cargo.toml":       parsers.ParseCargoToml,
	}

	// Language to file mappings
	languageMap := map[string][]string{
		"go":     {"go.mod"},
		"node":   {"package.json"},
		"java":   {"pom.xml"},
		"python": {"requirements.txt"},
		"rust":   {"Cargo.toml"},
		"all":    {"go.mod", "package.json", "pom.xml", "requirements.txt", "Cargo.toml"},
	}

	// Normalize language to lowercase for case-insensitive matching
	language = strings.ToLower(language)

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
