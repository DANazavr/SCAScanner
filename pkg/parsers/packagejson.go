package parsers

import (
	"SCAScanner/internal/models"
	"bufio"
	"os"
	"strings"
)

func ParsePackageJSON(filepath string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	isDependenciesSection := false
	isDevDependenciesSection := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, `"dependencies": {`) {
			isDependenciesSection = true
			continue
		}

		if isDependenciesSection {
			if strings.HasPrefix(line, `}`) || strings.HasPrefix(line, `},`) {
				isDependenciesSection = false
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				parts[0] = cleanVersion(parts[0])
				parts[1] = cleanVersion(parts[1])
				dependencies = append(dependencies, models.Dependency{
					Name:    strings.Trim(parts[0], `"`),
					Version: strings.Trim(parts[1], `"`),
				})
			}
		}
		if strings.HasPrefix(line, `"devDependencies": {`) {
			isDevDependenciesSection = true
			continue
		}
		if isDevDependenciesSection {
			if strings.HasPrefix(line, `}`) || strings.HasPrefix(line, `},`) {
				isDevDependenciesSection = false
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				parts[0] = cleanVersion(parts[0])
				parts[1] = cleanVersion(parts[1])
				dependencies = append(dependencies, models.Dependency{
					Name:    strings.Trim(parts[0], `"`),
					Version: strings.Trim(parts[1], `"`),
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return dependencies, nil
}

func cleanVersion(version string) string {
	// Убрать ^, ~, >=, <= и т.д.
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, "=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<")
	return version
}
