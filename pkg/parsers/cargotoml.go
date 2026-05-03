package parsers

import (
	"SCAScanner/internal/models"

	"os"

	"github.com/pelletier/go-toml/v2"
)

type CargoToml struct {
	Dependencies    map[string]interface{} `toml:"dependencies"`
	DevDependencies map[string]interface{} `toml:"dev-dependencies"`
}

func ParseCargoToml(filepath string) ([]models.Dependency, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var cargo CargoToml
	if err := toml.Unmarshal(data, &cargo); err != nil {
		return nil, err
	}

	var dependencies []models.Dependency

	parseDeps := func(deps map[string]interface{}) {
		for name, raw := range deps {
			version := extractCargoVersion(raw)
			if version == "" {
				continue
			}

			dependencies = append(dependencies, models.Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: "crates.io",
			})
		}
	}

	parseDeps(cargo.Dependencies)
	parseDeps(cargo.DevDependencies)

	return dependencies, nil
}

func extractCargoVersion(raw interface{}) string {
	switch v := raw.(type) {

	// actix-web = "4.0.1"
	case string:
		return cleanCargoVersion(v)

	// tokio = { version = "1.17.0", features = ["full"] }
	case map[string]interface{}:
		if versionRaw, exists := v["version"]; exists {
			if versionStr, ok := versionRaw.(string); ok {
				return cleanCargoVersion(versionStr)
			}
		}
	}

	return ""
}

func cleanCargoVersion(version string) string {
	prefixes := []string{
		"^", "~", "*",
		">=", "<=",
		">", "<",
		"=",
	}

	for _, p := range prefixes {
		version = trimPrefix(version, p)
	}

	return version
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
