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

	// Читаем файл целиком
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// Десериализуем JSON в структуру
	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	// Обрабатываем обычные зависимости
	for name, version := range pkg.Dependencies {
		dependencies = append(dependencies, models.Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "npm", // ОБЯЗАТЕЛЬНО
		})
	}

	// Обрабатываем dev-зависимости
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
	// Убираем кавычки, если они остались
	version = strings.Trim(version, "\"")

	// Регулярное выражение для удаления ^, ~, >=, <=, >, <
	re := regexp.MustCompile(`[~^>=<]+`)
	version = re.ReplaceAllString(version, "")

	return strings.TrimSpace(version)
}
