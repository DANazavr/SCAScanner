package reporters

import (
	"SCAScanner/internal/models"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

func GenerateJSONReport(deps []models.Dependency, vuln []models.Vulnerability, outpath string) error {
	statistics := calculateStatistics(vuln)
	report := models.ReportResult{
		Dependencies:    deps,
		Vulnerabilities: vuln,
		Statistics:      statistics,
		TotalDeps:       len(deps),
		Date:            time.Now().Format("2006-01-02 15:04:05"),
	}
	return saveReportAsJSON(report, outpath)
}

func calculateStatistics(vuln []models.Vulnerability) models.Statistics {
	var stats models.Statistics
	for _, v := range vuln {
		stats.Total++
		switch v.Severity {
		case "CRITICAL":
			stats.Critical++
		case "HIGH":
			stats.High++
		case "MEDIUM":
			stats.Medium++
		case "LOW":
			stats.Low++
		}
	}
	return stats
}

func saveReportAsJSON(report models.ReportResult, outpath string) error {
	file, err := os.Create(filepath.Join(outpath, "report.json"))
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err != nil {
		return err
	}
	return nil
}
