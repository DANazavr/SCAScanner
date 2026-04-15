package reporters

import (
	"SCAScanner/internal/models"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

const htmlTemplate = `
	<!DOCTYPE html>
	<html lang="ru">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Vulnerability Report</title>
		<style>
			* {
				margin: 0;
				padding: 0;
				box-sizing: border-box;
			}

			body {
				font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
				background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
				padding: 20px;
				min-height: 100vh;
			}

			.container {
				max-width: 1200px;
				margin: 0 auto;
				background: white;
				border-radius: 10px;
				box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
				overflow: visible;
			}

			header {
				background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
				color: white;
				padding: 30px;
				text-align: center;
			}

			header h1 {
				font-size: 2.5em;
				margin-bottom: 10px;
			}

			.scan.scan-info {
				background: rgba(255, 255, 255, 0.1);
				padding: 15px;
				border-radius: 5px;
				margin-top: 15px;
			}

			.stats {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
				gap: 20px;
				padding: 30px;
				background: #f8f9fa;
			}

			.stat-card {
				background: white;
				padding: 20px;
				border-radius: 8px;
				box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
				text-align: center;
			}

			.stat-card h3 {
				color: #666;
				font-size: 0.9em;
				margin-bottom: 10px;
				text-transform: uppercase;
			}

			.stat-card .number {
				font-size: 2.5em;
				font-weight: bold;
				margin: 10px 0;
			}

			.critical .number { color: #dc3545; }
			.high .number { color: #fd7e14; }
			.medium .number { color: #ffc107; }
			.low .number { color: #28a745; }

			.vulnerabilities {
				padding: 30px;
			}

			.vulnerabilities h2 {
				color: #333;
				margin-bottom: 20px;
				border-bottom: 3px solid #667eea;
				padding-bottom: 10px;
			}

			.vuln-item {
				background: white;
				border-left: 4px solid #667eea;
				padding: 20px;
				margin-bottom: 20px;
				border-radius: 5px;
				box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
			}

			.vuln-item.critical { border-left-color: #dc3545; }
			.vuln-item.high { border-left-color: #fd7e14; }
			.vuln-item.medium { border-left-color: #ffc107; }
			.vuln-item.low { border-left-color: #28a745; }

			.vuln-header {
				display: flex;
				justify-content: space-between;
				align-items: center;
				margin-bottom: 15px;
			}

			.vuln-id {
				font-size: 1.3em;
				font-weight: bold;
				color: #333;
			}

			.severity-badge {
				padding: 8px 20px;
				border-radius: 25px;
				font-size: 0.9em;
				font-weight: bold;
				color: grey;
				box-shadow: 0 2px 5px rgba(0,0,0,0.2);
			}

			.severity-badge.critical { background: #dc3545; }
			.severity-badge.high { background: #fd7e14; }
			.severity-badge.medium { background: #ffc107; color: #333; }
			.severity-badge.low { background: #28a745; }

			.vuln-detail {
				margin: 10px 0;
				color: #555;
			}

			.vuln-detail strong {
				color: #333;
			}

			.vuln-description {
				background: #f8f9fa;
				padding: 15px;
				border-radius: 5px;
				margin: 15px 0;
				line-height: 1.6;
			}

			footer {
				background: #333;
				color: white;
				text-align: center;
				padding: 20px;
			}

			#scrollTopBtn {
				display: none;
				position: fixed;
				bottom: 30px;
				right: 30px;
				z-index: 99;
				font-size: 18px;
				border: none;
				outline: none;
				background: #667eea;
				color: white;
				cursor: pointer;
				padding: 12px 16px;
				border-radius: 50%;
				box-shadow: 0 4px 10px rgba(0,0,0,0.3);
				transition: 0.3s;
			}

			#scrollTopBtn:hover {
				background: #5a67d8;
				transform: scale(1.1);
			}

			.stat-card {
				cursor: pointer;
				transition: 0.2s;
			}

			.stat-card:hover {
				transform: translateY(-5px);
				box-shadow: 0 5px 15px rgba(0,0,0,0.2);
			}

			.reset-btn {
				background: #a7a7a7;
				color: white;
				border: none;
				padding: 10px 20px;
				border-radius: 5px;
				cursor: pointer;
			}

			.reset-btn:hover {
				background: #555;
			}

			.stat-card.active {
				transform: translateY(-5px);
				box-shadow: 0 8px 20px rgba(0,0,0,0.3);
				border: 2px solid #667eea;
			}

			.stat-card.critical.active { border-color: #dc3545; }
			.stat-card.high.active { border-color: #fd7e14; }
			.stat-card.medium.active { border-color: #ffc107; }
			.stat-card.low.active { border-color: #28a745; }
		</style>
	</head>
	<body>
		<script>
			let activeFilters = new Set();

			function toggleFilter(card) {
				const level = card.dataset.level;

				if (activeFilters.has(level)) {
					activeFilters.delete(level);
					card.classList.remove("active");
				} else {
					activeFilters.add(level);
					card.classList.add("active");
				}

				applyFilters();
			}

			function applyFilters() {
				const items = document.querySelectorAll(".vuln-item");

				items.forEach(item => {
					const severity = item.dataset.severity;

					if (activeFilters.size === 0 || activeFilters.has(severity)) {
						item.style.display = "block";
					} else {
						item.style.display = "none";
					}
				});
			}

			function resetFilter() {
				activeFilters.clear();

				document.querySelectorAll(".stat-card").forEach(card => {
					card.classList.remove("active");
				});

				document.querySelectorAll(".vuln-item").forEach(item => {
					item.style.display = "block";
				});
			}
		</script>

		<button onclick="scrollToTop()" id="scrollTopBtn" title="Up">↑</button>

		<script>
			window.onscroll = function() {
				const btn = document.getElementById("scrollTopBtn");
				if (document.body.scrollTop > 300 || document.documentElement.scrollTop > 300) {
					btn.style.display = "block";
				} else {
					btn.style.display = "none";
				}
			};

			function scrollToTop() {
				window.scrollTo({
					top: 0,
					behavior: "smooth"
				});
			}
		</script>

		<div class="container">
			<header>
				<h1>🛡️ Vulnerability Report</h1>
				<div class="scan-info">
					<div>📅 Scan Date: {{.Date}}</div>
					<div>📦 Total Dependencies: {{.TotalDeps}}</div>
					<div>🔍 Vulnerabilities Found: {{.Statistics.Total}}</div>
				</div>
			</header>

			<div class="stats">
				<div class="stat-card critical" onclick="toggleFilter(this)" data-level="CRITICAL">
					<h3>Critical</h3>
					<div class="number">{{.Statistics.Critical}}</div>
				</div>
				<div class="stat-card high" onclick="toggleFilter(this)" data-level="HIGH">
					<h3>High</h3>
					<div class="number">{{.Statistics.High}}</div>
				</div>
				<div class="stat-card medium" onclick="toggleFilter(this)" data-level="MEDIUM">
					<h3>Medium</h3>
					<div class="number">{{.Statistics.Medium}}</div>
				</div>
				<div class="stat-card low" onclick="toggleFilter(this)" data-level="LOW">
					<h3>Low</h3>
					<div class="number">{{.Statistics.Low}}</div>
				</div>
			</div>

			<div style="text-align:center; margin: 5px;">
				<button onclick="resetFilter()" class="reset-btn">Reset filter</button>
			</div>

			<div class="vulnerabilities">
				<h2>Vulnerability Details</h2>
				{{range .Vulnerabilities}}
				<div class="vuln-item {{lower .Severity}}" data-severity="{{.Severity}}">
					<div class="vuln-header">
						<div class="vuln-id">{{.CVEID}}</div>
						<div class="severity-badge {{.Severity}}">
							{{if eq .Severity "CRITICAL"}}🔴{{end}}
							{{if eq .Severity "HIGH"}}🟠{{end}}
							{{if eq .Severity "MEDIUM"}}🟡{{end}}
							{{if eq .Severity "LOW"}}🟢{{end}}
							{{.Severity}} (CVSS: {{printf "%.1f" .CVSSScore}})
						</div>
					</div>
					<div class="vuln-detail">
						<strong>Affected Package:</strong> {{.AffectedPackage}}
					</div>
					<div class="vuln-description">
						{{.Description}}
					</div>
				</div>
				{{end}}
			</div>

			<footer>
				Generated by SCA Scanner
			</footer>
		</div>
	</body>
	</html>
	`

func GenerateHTMLReport(deps []models.Dependency, vuln []models.Vulnerability, outpath string) error {
	statistics := calculateStatistics(vuln)
	report := models.ReportResult{
		Dependencies:    deps,
		Vulnerabilities: vuln,
		Statistics:      statistics,
		TotalDeps:       len(deps),
		Date:            time.Now().Format("2006-01-02 15:04:05"),
	}
	return saveReportAsHTML(report, outpath)
}

func saveReportAsHTML(report models.ReportResult, outpath string) error {
	file, err := os.Create(filepath.Join(outpath, "report.html"))
	if err != nil {
		return err
	}
	defer file.Close()

	tmpl := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	})
	tmpl, err = tmpl.Parse(htmlTemplate)
	if err != nil {
		return err
	}
	if err := tmpl.Execute(file, report); err != nil {
		return err
	}
	return nil
}
