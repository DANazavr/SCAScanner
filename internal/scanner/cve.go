package scanner

import (
	"SCAScanner/internal/models"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type CVEItem struct {
	CVE struct {
		ID           string `json:"id"`
		PubishedDate string `json:"published"`
		LastModified string `json:"lastModified"`
		Description  []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CVSSMetricsV31 []struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
		} `json:"metrics"`
	} `json:"cve"`
}

type CVEResponce struct {
	Vulnerabilities []CVEItem `json:"vulnerabilities"`
}

func (vs *VulnScanner) SearchCVE(dependencyName string, dependencyVersion string) ([]models.Vulnerability, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s", url.QueryEscape(dependencyName))
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch CVE data: %s", resp.Status)
	}

	var cveResponce CVEResponce
	if err = json.NewDecoder(resp.Body).Decode(&cveResponce); err != nil {
		return nil, err
	}
	var vulnerabilities []models.Vulnerability
	for _, item := range cveResponce.Vulnerabilities {
		description := ""
		if len(item.CVE.Description) > 0 {
			description = item.CVE.Description[0].Value
		}
		severity := "UNKNOWN"
		cvssScore := 0.0
		if len(item.CVE.Metrics.CVSSMetricsV31) > 0 {
			severity = item.CVE.Metrics.CVSSMetricsV31[0].CVSSData.BaseSeverity
			cvssScore = item.CVE.Metrics.CVSSMetricsV31[0].CVSSData.BaseScore
		}
		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			CVEID:           item.CVE.ID,
			PublishedDate:   item.CVE.PubishedDate,
			LastModified:    item.CVE.LastModified,
			Description:     description, // Assuming the first description is in English
			Severity:        severity,
			SeverityClass:   severity, // You can map this to CSS classes in the HTML report
			AffectedPackage: dependencyName,
			CVSSScore:       cvssScore,
		})
	}
	return vulnerabilities, nil
}
