package scanner

import (
	"SCAScanner/internal/models"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// OSV API структуры
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

	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Aliases   []string `json:"aliases"`
}

func (vs *VulnScanner) SearchCVE(packageName string, packageVersion string, ecosystem string) ([]models.Vulnerability, error) {
	// Временный метод, который просто вызывает OSV поиск
	// В будущем можно добавить кэширование или более сложную логику
	return vs.SearchOSV(packageName, packageVersion, ecosystem)
}

func (vs *VulnScanner) SearchOSV(packageName string, packageVersion string, ecosystem string) ([]models.Vulnerability, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Формируем запрос
	reqBody := OSVRequest{
		Package: OSVPackage{
			Name:      packageName,
			Ecosystem: ecosystem,
		},
	}

	// Добавляем версию только если указана
	if packageVersion != "" {
		reqBody.Version = cleanVersion(packageVersion)
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	// Отправляем POST запрос
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

	// Парсим ответ
	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, err
	}

	// Преобразуем в наши модели
	var vulnerabilities []models.Vulnerability
	for _, vuln := range osvResp.Vulns {
		// Извлекаем CVE ID из aliases
		cveID := extractCVEID(vuln)

		// Извлекаем severity и CVSS
		severity, cvssScore := extractSeverityAndScore(vuln)

		// Пропускаем если нет severity
		if severity == "" || severity == "UNKNOWN" {
			continue
		}

		// Формируем описание
		description := ""

		if vuln.Summary != "" && vuln.Details != "" {
			// Если есть оба - объединяем
			description = vuln.Summary + ". " + vuln.Details
		} else if vuln.Details != "" {
			// Если только details
			description = vuln.Details
		} else if vuln.Summary != "" {
			// Если только summary
			description = vuln.Summary
		}

		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			CVEID:           cveID,
			PublishedDate:   vuln.Published,
			LastModified:    vuln.Modified,
			Description:     description,
			Severity:        severity,
			CVSSScore:       cvssScore,
			AffectedPackage: packageName,
		})
	}

	return vulnerabilities, nil
}

// Извлекает CVE ID из aliases или использует OSV ID
func extractCVEID(vuln OSVVulnerability) string {
	// Ищем CVE в aliases
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}

	// Если нет CVE, используем OSV ID
	return vuln.ID
}

// Извлекает severity и CVSS score
func extractSeverityAndScore(vuln OSVVulnerability) (string, float64) {
	// Пробуем извлечь из severity массива
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			score := parseCVSSScore(sev.Score)
			severity := scoreToSeverity(score)
			return severity, score
		}
	}

	// Пробуем database_specific
	if vuln.DatabaseSpecific != nil {
		if sevStr, ok := vuln.DatabaseSpecific["severity"].(string); ok {
			severity := normalizeSeverity(sevStr)
			// Пробуем найти score
			if cvssScore, ok := vuln.DatabaseSpecific["cvss_score"].(float64); ok {
				return severity, cvssScore
			}
			// Если нет score, оцениваем примерно
			score := severityToScore(severity)
			return severity, score
		}
	}

	return "UNKNOWN", 0.0
}

// Парсит CVSS score из строки типа "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
func parseCVSSScore(cvssString string) float64 {
	// Упрощённый парсинг - ищем базовый score
	// Для полноценного парсинга нужна CVSS библиотека

	// Пробуем найти число в начале после двоеточия
	re := regexp.MustCompile(`CVSS:[\d.]+/.*`)
	if !re.MatchString(cvssString) {
		return 0.0
	}

	// Вычисляем приблизительный score на основе компонентов
	// Это упрощение - в реальности нужен полный CVSS калькулятор
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

// Конвертирует CVSS score в severity
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

// Нормализует severity строку
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

// Примерный score для severity
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

// Очищает версию от префиксов
func cleanVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")
	return version
}
