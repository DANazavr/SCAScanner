package parsers

import (
	"SCAScanner/internal/models"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

type Project struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`

	Parent *Parent `xml:"parent"`

	Properties map[string]string `xml:"properties>*"`

	Dependencies         []PomDependency `xml:"dependencies>dependency"`
	DependencyManagement struct {
		Dependencies []PomDependency `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`

	Modules []string `xml:"modules>module"`
}

type Parent struct {
	GroupID      string `xml:"groupId"`
	ArtifactID   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

type PomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

func ParsePomXML(path string) ([]models.Dependency, error) {
	visited := make(map[string]bool)
	return parsePom(path, visited)
}

func parsePom(path string, visited map[string]bool) ([]models.Dependency, error) {
	if visited[path] {
		return nil, nil
	}
	visited[path] = true

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var project Project
	if err := xml.NewDecoder(file).Decode(&project); err != nil {
		return nil, err
	}

	baseDir := filepath.Dir(path)

	parentProps := map[string]string{}
	// parentDM := map[string]string{}

	if project.Parent != nil {
		parentPath := filepath.Join(baseDir, project.Parent.RelativePath)
		if parentPath == "" {
			parentPath = "../pom.xml"
		}
		parentDeps, _ := parsePom(parentPath, visited)
		_ = parentDeps // можно расширить при необходимости
	}

	props := mergeMaps(parentProps, project.Properties)

	dm := map[string]string{}
	for _, d := range project.DependencyManagement.Dependencies {
		key := d.GroupID + ":" + d.ArtifactID
		dm[key] = resolveProperty(d.Version, props)
	}

	var result []models.Dependency

	for _, d := range project.Dependencies {

		if d.Scope == "test" || d.Scope == "provided" {
			continue
		}

		name := d.GroupID + ":" + d.ArtifactID

		version := resolveProperty(d.Version, props)

		if version == "" {
			if v, ok := dm[name]; ok {
				version = v
			}
		}

		if name != ":" && version != "" {
			result = append(result, models.Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: "Maven",
			})
		}
	}

	// 🔥 модули (multi-module)
	for _, module := range project.Modules {
		modulePath := filepath.Join(baseDir, module, "pom.xml")
		subDeps, err := parsePom(modulePath, visited)
		if err == nil {
			result = append(result, subDeps...)
		}
	}

	return result, nil
}

func resolveProperty(val string, props map[string]string) string {
	val = strings.TrimSpace(val)

	if strings.HasPrefix(val, "${") && strings.HasSuffix(val, "}") {
		key := strings.TrimSuffix(strings.TrimPrefix(val, "${"), "}")
		if v, ok := props[key]; ok {
			return v
		}
	}

	return val
}

func mergeMaps(a, b map[string]string) map[string]string {
	res := make(map[string]string)

	for k, v := range a {
		res[k] = v
	}
	for k, v := range b {
		res[k] = v
	}

	return res
}
