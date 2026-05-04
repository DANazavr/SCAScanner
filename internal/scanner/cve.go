package scanner

import (
	"SCAScanner/internal/models"
	"SCAScanner/internal/recommendations"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/rogpeppe/go-internal/semver"
)

type OSVRequest struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

type OSVVulnerability struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Details string `json:"details"`

	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`

	DatabaseSpecific map[string]interface{} `json:"database_specific"`

	Affected []struct {
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced,omitempty"`
				Fixed        string `json:"fixed,omitempty"`
				LastAffected string `json:"last_affected,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`

	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Aliases   []string `json:"aliases"`
}

func (vs *VulnScanner) SearchCVE(packageName string, packageVersion string, ecosystem string) ([]models.Vulnerability, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cacheKey := fmt.Sprintf("cve:%s:%s", packageName, packageVersion)

	if vs.cache != nil {
		if vulns, err := vs.cache.Get(ctx, cacheKey); err == nil {
			return vulns, nil
		}
	}

	vuln, err := vs.SearchOSV(packageName, packageVersion, ecosystem)
	if err == nil && len(vuln) > 0 {
		if vs.cache != nil {
			_ = vs.cache.Set(ctx, cacheKey, vuln)
		}
		return vuln, nil
	} else if err != nil {
		return nil, err
	}
	emptyVulns := []models.Vulnerability{}
	if vs.cache != nil {
		_ = vs.cache.Set(ctx, cacheKey, emptyVulns)
	}
	return emptyVulns, nil
}

func (vs *VulnScanner) SearchOSV(packageName string, packageVersion string, ecosystem string) ([]models.Vulnerability, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	reqBody := OSVRequest{
		Package: OSVPackage{
			Name:      packageName,
			Ecosystem: ecosystem,
		},
	}

	if packageVersion != "" {
		reqBody.Version = cleanVersion(packageVersion)
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(
		"https://api.osv.dev/v1/query",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API error: %s", resp.Status)
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, err
	}

	var vulnerabilities []models.Vulnerability
	for _, vuln := range osvResp.Vulns {
		cveID := extractCVEID(vuln)

		severity, cvssScore := extractSeverityAndScore(vuln)

		if severity == "" || severity == "UNKNOWN" {
			continue
		}

		fixedVersion := extractFixedVersion(vuln, cleanVersion(packageVersion))

		description := ""

		if vuln.Summary != "" && vuln.Details != "" {
			description = vuln.Summary + ". " + vuln.Details
		} else if vuln.Details != "" {
			description = vuln.Details
		} else if vuln.Summary != "" {
			description = vuln.Summary
		}

		v := models.Vulnerability{
			CVEID:           cveID,
			PublishedDate:   vuln.Published,
			LastModified:    vuln.Modified,
			CurrentVersion:  cleanVersion(packageVersion),
			FixedVersion:    fixedVersion,
			Description:     description,
			Severity:        severity,
			CVSSScore:       cvssScore,
			AffectedPackage: packageName,
			Ecosystem:       ecosystem,
		}
		v.Recommendation = recommendations.GenerateRecommendation(v)

		vulnerabilities = append(vulnerabilities, v)
	}

	return vulnerabilities, nil
}

func extractCVEID(vuln OSVVulnerability) string {
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}

	return vuln.ID
}

func extractSeverityAndScore(vuln OSVVulnerability) (string, float64) {
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			score := parseCVSSScore(sev.Score)
			severity := scoreToSeverity(score)
			return severity, score
		}
	}

	if vuln.DatabaseSpecific != nil {
		if sevStr, ok := vuln.DatabaseSpecific["severity"].(string); ok {
			severity := normalizeSeverity(sevStr)
			if cvssScore, ok := vuln.DatabaseSpecific["cvss_score"].(float64); ok {
				return severity, cvssScore
			}
			score := severityToScore(severity)
			return severity, score
		}
	}

	return "UNKNOWN", 0.0
}

func extractFixedVersion(vuln OSVVulnerability, currentVersion string) string {
	currentVersion = normalize(currentVersion)
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			var introduced string
			for _, event := range r.Events {
				if event.Introduced != "" {
					introduced = normalize(event.Introduced)
				}
				if event.Fixed != "" {
					fixedVersion := normalize(event.Fixed)
					if versionInRange(currentVersion, introduced, fixedVersion) {
						return cleanVersion(event.Fixed)
					}
				}
			}
		}
	}

	return ""
}

func normalize(v string) string {
	if v == "" {
		return ""
	}
	if v[0] != 'v' {
		return "v" + v
	}
	return v
}

func versionInRange(current, introduced, fixed string) bool {
	if !semver.IsValid(current) {
		return false
	}

	if introduced != "" && semver.Compare(current, introduced) < 0 {
		return false
	}

	if fixed != "" && semver.Compare(current, fixed) >= 0 {
		return false
	}

	return true
}

func parseCVSSScore(cvssString string) float64 {
	re := regexp.MustCompile(`CVSS:[\d.]+/.*`)
	if !re.MatchString(cvssString) {
		return 0.0
	}

	score := 0.0

	if strings.Contains(cvssString, "C:H") {
		score += 3.0
	} else if strings.Contains(cvssString, "C:L") {
		score += 1.0
	}

	if strings.Contains(cvssString, "I:H") {
		score += 3.0
	} else if strings.Contains(cvssString, "I:L") {
		score += 1.0
	}

	if strings.Contains(cvssString, "A:H") {
		score += 3.0
	} else if strings.Contains(cvssString, "A:L") {
		score += 1.0
	}

	if score > 10.0 {
		score = 10.0
	}

	return score
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func normalizeSeverity(sev string) string {
	sev = strings.ToUpper(strings.TrimSpace(sev))

	switch sev {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return sev
	case "MODERATE":
		return "MEDIUM"
	default:
		return "UNKNOWN"
	}
}

func severityToScore(severity string) float64 {
	switch severity {
	case "CRITICAL":
		return 9.5
	case "HIGH":
		return 7.5
	case "MEDIUM":
		return 5.0
	case "LOW":
		return 2.5
	default:
		return 0.0
	}
}

func cleanVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")
	return version
}
