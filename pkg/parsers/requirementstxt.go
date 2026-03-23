package parsers

import (
	"SCAScanner/internal/models"
	"bufio"
	"os"
	"strings"
)

func ParseRequirementsTxt(filepath string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		operators := []string{"==", ">=", "<=", "~="}

		for _, op := range operators {
			if strings.Contains(line, op) {
				parts := strings.Split(line, "==")
				if len(parts) == 2 {
					dependencies = append(dependencies, models.Dependency{
						Name:    parts[0],
						Version: parts[1],
					})
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return dependencies, nil
}
