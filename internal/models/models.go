package models

type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Vulnerability struct {
	CVEID           string  `json:"cve_id"`
	PublishedDate   string  `json:"published"`
	LastModified    string  `json:"lastModified"`
	Description     string  `json:"description"`
	Severity        string  `json:"severity"`
	SeverityClass   string  `json:"severity_class"`
	CVSSScore       float64 `json:"cvss_score"`
	AffectedPackage string  `json:"affected_package"`
}

type Statistics struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
}

type ReportResult struct {
	Dependencies    []Dependency    `json:"dependencies"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Statistics      Statistics      `json:"statistics"`
	TotalDeps       int             `json:"total_deps"`
	Date            string          `json:"scan_date"`
}
