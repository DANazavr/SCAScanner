package parsers

import (
	"SCAScanner/internal/models"
	"bufio"
	"os"
	"regexp"
	"strings"
)

func ParseRequirementsTxt(filepath string) ([]models.Dependency, error) {
	var dependencies []models.Dependency

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	re := regexp.MustCompile(`^([A-Za-z0-9_\-\.]+)==([^\s]+)`)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			dependencies = append(dependencies, models.Dependency{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: "PyPI",
			})
		}
	}
	return dependencies, nil
}
