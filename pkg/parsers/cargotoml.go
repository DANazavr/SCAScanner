package parsers

import (
	"SCAScanner/internal/models"
	"bufio"
	"os"
	"strings"
)

func ParseCargoToml(filepath string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inDependenciesSection := false
	inDevDependenciesSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[dependencies]" {
			inDependenciesSection = true
			inDevDependenciesSection = false
			continue
		}
		if line == "[dev-dependencies]" {
			inDevDependenciesSection = true
			inDependenciesSection = false
			continue
		}

		if strings.HasPrefix(line, "[") && line != "[dependencies]" && line != "[dev-dependencies]" {
			inDependenciesSection = false
			inDevDependenciesSection = false
			continue
		}

		if inDependenciesSection || inDevDependenciesSection {
			if strings.Contains(line, "=") {
				parts := strings.Split(line, "=")
				if len(parts) >= 2 {
					name := strings.TrimSpace(parts[0])
					versionPart := strings.TrimSpace(strings.Join(parts[1:], "="))

					version := extractVersion(versionPart)
					if version != "" && name != "" {
						dependencies = append(dependencies, models.Dependency{
							Name:    name,
							Version: version,
						})
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return dependencies, nil
}

func extractVersion(versionString string) string {
	versionString = strings.TrimSpace(versionString)

	if strings.HasPrefix(versionString, "\"") && strings.HasSuffix(versionString, "\"") {
		version := strings.Trim(versionString, "\"")
		return cleanCargoVersion(version)
	}

	if strings.HasPrefix(versionString, "{") {
		if idx := strings.Index(versionString, "version"); idx != -1 {
			remainder := versionString[idx+7:]
			if idx := strings.Index(remainder, "="); idx != -1 {
				remainder = remainder[idx+1:]
				if strings.Contains(remainder, "\"") {
					parts := strings.Split(remainder, "\"")
					if len(parts) >= 2 {
						return cleanCargoVersion(parts[1])
					}
				}
			}
		}
	}

	return ""
}

func cleanCargoVersion(version string) string {
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, "*")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, "=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<")
	return strings.TrimSpace(version)
}
