package output_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/v2/internal/grouper"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestPrintOutputResults_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("Error writing output: %s", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestBuildResults_ExactEcosystemGrouping(t *testing.T) {
	t.Parallel()

	packageWithVuln := func(name, ecosystem, vulnID string) models.PackageVulns {
		return models.PackageVulns{
			Package: models.PackageInfo{
				Name:      name,
				Version:   "1.0.0",
				Ecosystem: ecosystem,
			},
			Vulnerabilities: []*osvschema.Vulnerability{{Id: vulnID}},
			Groups:          []models.GroupInfo{{IDs: []string{vulnID}}},
		}
	}

	vulnResult := &models.VulnerabilityResults{
		Results: []models.PackageSource{{
			Source: models.SourceInfo{Path: "mixed.sbom", Type: models.SourceTypeSBOM},
			Packages: []models.PackageVulns{
				packageWithVuln("base-package", "Alpine", "OSV-BASE"),
				packageWithVuln("versioned-package", "Alpine:v3.18", "OSV-VERSIONED"),
			},
		}},
	}

	got := make(map[string][]string)
	for _, ecosystem := range output.BuildResults(vulnResult).Ecosystems {
		for _, source := range ecosystem.Sources {
			for _, pkg := range source.Packages {
				got[ecosystem.Name] = append(got[ecosystem.Name], pkg.Name)
			}
		}
	}
	want := map[string][]string{
		"Alpine":       {"base-package"},
		"Alpine:v3.18": {"versioned-package"},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("BuildResults() ecosystem packages mismatch (-want +got):\n%s", diff)
	}
}

// buildAliasGroupResult builds the output result for a single npm package
// affected by one alias group of two records: CVE-2025-0001 (which sorts
// first and therefore becomes the group's representative ID) and
// GHSA-aaaa-bbbb-cccc (which lists the CVE as an alias). Each record carries a
// fix event for the package only when its respective fix argument is non-empty.
// Groups are built the same way the scanner builds them.
func buildAliasGroupResult(t *testing.T, cveFix, ghsaFix string) output.Result {
	t.Helper()

	affected := func(fixed string) []*osvschema.Affected {
		events := []*osvschema.Event{{Introduced: "0"}}
		if fixed != "" {
			events = append(events, &osvschema.Event{Fixed: fixed})
		}

		return []*osvschema.Affected{{
			Package: &osvschema.Package{Name: "mine1", Ecosystem: "npm"},
			Ranges:  []*osvschema.Range{{Type: osvschema.Range_SEMVER, Events: events}},
		}}
	}

	pkg := models.PackageVulns{
		Package: models.PackageInfo{Name: "mine1", Version: "1.2.3", Ecosystem: "npm"},
		Vulnerabilities: []*osvschema.Vulnerability{
			{Id: "CVE-2025-0001", Summary: "the CVE record", Affected: affected(cveFix)},
			{Id: "GHSA-aaaa-bbbb-cccc", Summary: "the GHSA record", Aliases: []string{"CVE-2025-0001"}, Affected: affected(ghsaFix)},
		},
	}
	pkg.Groups = grouper.Build(pkg, false)

	return output.BuildResults(&models.VulnerabilityResults{
		Results: []models.PackageSource{{
			Source:   models.SourceInfo{Path: "package-lock.json", Type: models.SourceTypeProjectPackage},
			Packages: []models.PackageVulns{pkg},
		}},
	})
}

// onlyRegularVuln extracts the single package and its single regular
// vulnerability from a result built by buildAliasGroupResult.
func onlyRegularVuln(t *testing.T, result output.Result) (output.PackageResult, output.VulnResult) {
	t.Helper()

	if len(result.Ecosystems) != 1 || len(result.Ecosystems[0].Sources) != 1 || len(result.Ecosystems[0].Sources[0].Packages) != 1 {
		t.Fatalf("expected exactly one ecosystem, source and package, got %+v", result.Ecosystems)
	}

	pkg := result.Ecosystems[0].Sources[0].Packages[0]
	if len(pkg.RegularVulns) != 1 {
		t.Fatalf("expected exactly one regular vulnerability, got %+v", pkg.RegularVulns)
	}

	return pkg, pkg.RegularVulns[0]
}

func TestBuildResults_AliasGroupFixBackfill(t *testing.T) {
	t.Parallel()

	// the representative record (CVE-2025-0001) carries no fix event, while the
	// other advisory in the group publishes the fix as version 1.4.0
	pkg, vuln := onlyRegularVuln(t, buildAliasGroupResult(t, "", "1.4.0"))

	if vuln.ID != "CVE-2025-0001" {
		t.Errorf("expected the group representative ID to be CVE-2025-0001, got %q", vuln.ID)
	}

	if !vuln.IsFixable {
		t.Error("expected the group to be fixable from its member record's fix event")
	}

	if vuln.FixedVersion != "1.4.0" {
		t.Errorf("expected the member record's fixed version to be backfilled, got %q", vuln.FixedVersion)
	}

	if got := pkg.VulnCount.FixableCount.Fixed; got != 1 {
		t.Errorf("expected 1 fixable vulnerability in the counts, got %d", got)
	}

	if pkg.FixedVersion != "1.4.0" {
		t.Errorf("expected the package fixed version to be 1.4.0, got %q", pkg.FixedVersion)
	}
}

func TestBuildResults_FixEventPositionContrast(t *testing.T) {
	t.Parallel()

	// the group's displayed fix must not depend on which member record of the
	// alias group carries the fix event
	tests := []struct {
		name    string
		cveFix  string
		ghsaFix string
	}{
		{name: "fix_on_the_representative_record", cveFix: "1.4.0", ghsaFix: ""},
		{name: "fix_on_the_other_record", cveFix: "", ghsaFix: "1.4.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, vuln := onlyRegularVuln(t, buildAliasGroupResult(t, tt.cveFix, tt.ghsaFix))

			if !vuln.IsFixable || vuln.FixedVersion != "1.4.0" {
				t.Errorf("expected fixable with fixed version 1.4.0, got fixable=%t fixed=%q", vuln.IsFixable, vuln.FixedVersion)
			}
		})
	}
}

func TestBuildResults_ConflictingMemberFixVersions(t *testing.T) {
	t.Parallel()

	// member records publishing different fixed versions for the same group are
	// aggregated to the highest version, so that upgrading to it resolves every
	// member advisory; the result must not depend on record order
	tests := []struct {
		name    string
		cveFix  string
		ghsaFix string
	}{
		{name: "higher_fix_on_the_other_record", cveFix: "1.2.4", ghsaFix: "1.4.0"},
		{name: "higher_fix_on_the_representative_record", cveFix: "1.4.0", ghsaFix: "1.2.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkg, vuln := onlyRegularVuln(t, buildAliasGroupResult(t, tt.cveFix, tt.ghsaFix))

			if !vuln.IsFixable || vuln.FixedVersion != "1.4.0" {
				t.Errorf("expected fixable with fixed version 1.4.0, got fixable=%t fixed=%q", vuln.IsFixable, vuln.FixedVersion)
			}

			if pkg.FixedVersion != "1.4.0" {
				t.Errorf("expected the package fixed version to be 1.4.0, got %q", pkg.FixedVersion)
			}
		})
	}
}
