package parsers

import (
	"SCAScanner/internal/models"
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

type PackageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func ParsePackageJSON(filepath string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	for name, version := range pkg.Dependencies {
		dependencies = append(dependencies, models.Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "npm",
		})
	}

	for name, version := range pkg.DevDependencies {
		dependencies = append(dependencies, models.Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "npm",
		})
	}

	return dependencies, nil
}

func cleanVersion(version string) string {
	version = strings.Trim(version, "\"")

	re := regexp.MustCompile(`[~^>=<]+`)
	version = re.ReplaceAllString(version, "")

	return strings.TrimSpace(version)
}
