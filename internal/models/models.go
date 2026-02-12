package models

import "time"

type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Vulnerability struct {
	CVEID           string    `json:"cve_id"`
	Description     string    `json:"description"`
	Severity        string    `json:"severity"`
	AffectedPackage string    `json:"affected_package"`
	CVSSScore       float64   `json:"cvss_score"`
	Date            time.Time `json:"date"`
}

type ReportResult struct {
	Dependencies    []Dependency    `json:"dependencies"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Date            time.Time       `json:"date"`
}
