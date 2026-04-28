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
	Scan(string) ([]models.Dependency, error)
	Analyze() error
}

type VulnScanner struct{}

func New() *VulnScanner {
	return &VulnScanner{}
}

func (vs *VulnScanner) Scan(projectPath string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	files := map[string]func(string) ([]models.Dependency, error){
		"go.mod":           parsers.ParseGoMod,
		"package.json":     parsers.ParsePackageJSON,
		"pom.xml":          parsers.ParsePomXML,
		"requirements.txt": parsers.ParseRequirementsTxt,
		"Сargo.toml":       parsers.ParseCargoToml,
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
