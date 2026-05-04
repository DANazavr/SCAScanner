package recommendations

import (
	"SCAScanner/internal/models"
	"fmt"
)

func GenerateRecommendation(v models.Vulnerability) string {
	if v.FixedVersion != "" {
		return buildUpgradeMessage(v)
	}

	switch v.Severity {
	case "CRITICAL", "HIGH":
		return fmt.Sprintf(
			"No patched version is available for %s (%s). Consider removing or replacing this dependency, or apply vendor patches if available.",
			v.AffectedPackage,
			v.CVEID,
		)

	case "MEDIUM":
		return fmt.Sprintf(
			"No fixed version for %s (%s). Limit exposure, avoid vulnerable functionality, and monitor for updates.",
			v.AffectedPackage,
			v.CVEID,
		)

	default:
		return fmt.Sprintf(
			"Monitor %s (%s) for updates and upgrade when a fix becomes available.",
			v.AffectedPackage,
			v.CVEID,
		)
	}
}

func buildUpgradeMessage(v models.Vulnerability) string {
	base := fmt.Sprintf(
		"Upgrade %s from %s to %s to fix %s.",
		v.AffectedPackage,
		v.CurrentVersion,
		v.FixedVersion,
		v.CVEID,
	)

	cmd := buildCommand(v)

	if cmd != "" {
		return base + " " + cmd
	}

	return base
}

func buildCommand(v models.Vulnerability) string {
	switch v.Ecosystem {
	case "npm":
		return fmt.Sprintf("Run: npm install %s@%s.", v.AffectedPackage, v.FixedVersion)

	case "Go":
		return fmt.Sprintf("Run: go get %s@%s.", v.AffectedPackage, v.FixedVersion)

	case "PyPI":
		return fmt.Sprintf("Run: pip install %s==%s.", v.AffectedPackage, v.FixedVersion)

	case "Maven":
		return fmt.Sprintf("Update version in pom.xml to %s.", v.FixedVersion)

	case "crates.io":
		return fmt.Sprintf("Update dependency version to %s in Cargo.toml.", v.FixedVersion)

	default:
		return ""
	}
}
