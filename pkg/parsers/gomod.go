package parsers

import (
	"SCAScanner/internal/models"
	"bufio"
	"os"
	"strings"
)

func ParseGoMod(filepath string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inRequireBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}

		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
		}

		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				dependencies = append(dependencies, models.Dependency{
					Name:    parts[0],
					Version: parts[1],
				})
			}
			continue // ВАЖНО: продолжаем цикл
		}

		if inRequireBlock && line != "" {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				dep := models.Dependency{
					Name:    parts[0],
					Version: parts[1],
				}
				dependencies = append(dependencies, dep)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return dependencies, nil
}
