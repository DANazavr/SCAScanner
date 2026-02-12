package scanner

import (
	"SCAScanner/internal/models"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type CVEItem struct {
	CVEID       string    `json:"cve_id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSSScore   float64   `json:"cvss_score"`
	Date        time.Time `json:"published_date"`
}

type CVEResponce struct {
	Vulnerabilities []CVEItem `json:"vulnerabilities"`
}

func SearchCVE(dependencyName string) ([]models.Vulnerability, error) {
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
		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			CVEID:           item.CVEID,
			Description:     item.Description,
			Severity:        item.Severity,
			AffectedPackage: dependencyName,
			CVSSScore:       item.CVSSScore,
			Date:            item.Date,
		})
	}
	return vulnerabilities, nil
}
