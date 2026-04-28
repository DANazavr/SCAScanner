package scanner

import (
	"SCAScanner/internal/models"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"time"
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

// OSV structures for Open Source Vulnerabilities API
type OSVVulnerability struct {
	ID       string    `json:"id"`
	Published string   `json:"published"`
	Modified string    `json:"modified"`
	Summary  string    `json:"summary"`
	Severity []OSVSeverity `json:"severity"`
	Details  string    `json:"details"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	} `json:"affected"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// RateLimiter controls request rate
type RateLimiter struct {
	ticker *time.Ticker
	done   chan bool
}

var nvdLimiter *RateLimiter
var osvLimiter *RateLimiter

func init() {
	// NVD API allows ~6 requests per second (with recommended delay)
	nvdLimiter = NewRateLimiter(200 * time.Millisecond)
	// OSV API has more lenient limits
	osvLimiter = NewRateLimiter(100 * time.Millisecond)
}

func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{
		ticker: time.NewTicker(interval),
		done:   make(chan bool),
	}
}

func (rl *RateLimiter) Wait() {
	<-rl.ticker.C
}

func (vs *VulnScanner) SearchCVE(dependencyName string, dependencyVersion string) ([]models.Vulnerability, error) {
	// Try NVD first with backoff
	vulns, err := vs.searchNVD(dependencyName, dependencyVersion)
	if err == nil && len(vulns) > 0 {
		return vulns, nil
	}

	// If NVD fails or returns nothing, try OSV as fallback
	vulns, osvErr := vs.searchOSV(dependencyName, dependencyVersion)
	if osvErr == nil && len(vulns) > 0 {
		return vulns, nil
	}

	// If both fail, return error from NVD (primary source)
	if err != nil {
		return nil, err
	}
	if osvErr != nil {
		return nil, osvErr
	}

	return []models.Vulnerability{}, nil
}

func (vs *VulnScanner) searchNVD(dependencyName string, dependencyVersion string) ([]models.Vulnerability, error) {
	nvdLimiter.Wait()

	requestURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s", url.QueryEscape(dependencyName))

	// Implement exponential backoff for rate limiting
	maxRetries := 3
	var resp *http.Response
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err = http.Get(requestURL)
		if err != nil {
			return nil, err
		}

		// Handle rate limiting
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			backoffDuration := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			fmt.Printf("NVD rate limit hit, waiting %v before retry...\n", backoffDuration)
			time.Sleep(backoffDuration)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("NVD: failed to fetch CVE data: %s", resp.Status)
		}

		break
	}

	if resp == nil {
		return nil, fmt.Errorf("NVD: failed after retries")
	}
	defer resp.Body.Close()

	var cveResponse CVEResponce
	if err = json.NewDecoder(resp.Body).Decode(&cveResponse); err != nil {
		return nil, err
	}

	return vs.parseNVDResponse(cveResponse, dependencyName), nil
}

func (vs *VulnScanner) searchOSV(dependencyName string, dependencyVersion string) ([]models.Vulnerability, error) {
	osvLimiter.Wait()

	// OSV query format
	queryPayload := map[string]interface{}{
		"package": map[string]string{
			"purl": fmt.Sprintf("pkg:npm/%s@%s", dependencyName, dependencyVersion),
		},
	}

	jsonPayload, err := json.Marshal(queryPayload)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(
		"https://api.osv.dev/v1/query",
		"application/json",
		bytes.NewReader(jsonPayload),
	)

	if err != nil {
		return nil, fmt.Errorf("OSV: request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV: failed to fetch data: %s", resp.Status)
	}

	var osvResponse OSVResponse
	if err = json.NewDecoder(resp.Body).Decode(&osvResponse); err != nil {
		return nil, fmt.Errorf("OSV: failed to parse response: %v", err)
	}

	return vs.parseOSVResponse(osvResponse, dependencyName), nil
}

func (vs *VulnScanner) parseNVDResponse(resp CVEResponce, dependencyName string) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	for _, item := range resp.Vulnerabilities {
		severity := "UNKNOWN"
		cvssScore := 0.0

		if len(item.CVE.Metrics.CVSSMetricsV31) > 0 {
			severity = item.CVE.Metrics.CVSSMetricsV31[0].CVSSData.BaseSeverity
			cvssScore = item.CVE.Metrics.CVSSMetricsV31[0].CVSSData.BaseScore
		} else {
			continue
		}

		description := ""
		if len(item.CVE.Description) > 0 {
			description = item.CVE.Description[0].Value
		}

		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			CVEID:           item.CVE.ID,
			PublishedDate:   item.CVE.PubishedDate,
			LastModified:    item.CVE.LastModified,
			Description:     description,
			Severity:        severity,
			AffectedPackage: dependencyName,
			CVSSScore:       cvssScore,
		})
	}

	return vulnerabilities
}

func (vs *VulnScanner) parseOSVResponse(resp OSVResponse, dependencyName string) []models.Vulnerability {
	var vulnerabilities []models.Vulnerability

	for _, vuln := range resp.Vulns {
		severity := "UNKNOWN"
		cvssScore := 0.0

		if len(vuln.Severity) > 0 {
			severity = vuln.Severity[0].Type
		}

		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			CVEID:           vuln.ID,
			PublishedDate:   vuln.Published,
			LastModified:    vuln.Modified,
			Description:     vuln.Summary,
			Severity:        severity,
			AffectedPackage: dependencyName,
			CVSSScore:       cvssScore,
		})
	}

	return vulnerabilities
}
