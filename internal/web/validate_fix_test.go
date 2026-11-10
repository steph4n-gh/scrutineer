package web

import (
	"encoding/json"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestClassifyFixValidation(t *testing.T) {
	const baselineID, fixID = uint(10), uint(20)
	baseline := []db.Finding{
		{ID: 1, Fingerprint: "fp-survive", LastSeenScanID: fixID},       // re-observed by the fix scan
		{ID: 2, Fingerprint: "fp-resolved", LastSeenScanID: baselineID}, // missed by the fix scan
		{ID: 3, Fingerprint: "fp-stale", LastSeenScanID: 0},             // never re-observed at all
	}
	fixNew := []db.Finding{{ID: 4, Fingerprint: "fp-new", ScanID: fixID}}

	resolved, surviving, newF := classifyFixValidation(baseline, fixNew, []uint{1})

	if len(surviving) != 1 || surviving[0].ID != 1 {
		t.Fatalf("surviving = %+v, want [id 1]", surviving)
	}
	if len(resolved) != 2 {
		t.Fatalf("resolved = %+v, want 2 (ids 2,3)", resolved)
	}
	if len(newF) != 1 || newF[0].ID != 4 {
		t.Fatalf("new = %+v, want [id 4]", newF)
	}
}

func TestClassifyFixValidation_empty(t *testing.T) {
	resolved, surviving, newF := classifyFixValidation(nil, nil, nil)
	if len(resolved) != 0 || len(surviving) != 0 || len(newF) != 0 {
		t.Fatalf("expected all empty, got resolved=%d s=%d n=%d", len(resolved), len(surviving), len(newF))
	}
}

func TestBuildFixValidationReport(t *testing.T) {
	const baselineID, fixID = uint(10), uint(20)
	fixScan := db.Scan{ID: fixID, Ref: "fix-branch", SkillName: "security-deep-dive", Commit: "abc123"}
	baseline := []db.Finding{
		{ID: 1, Fingerprint: "b", Title: "low survivor", Severity: "Low", LastSeenScanID: fixID},
		{ID: 2, Fingerprint: "a", Title: "critical survivor", Severity: "Critical", LastSeenScanID: fixID},
		{ID: 3, Fingerprint: "c", Title: "resolved one", Severity: "High", LastSeenScanID: baselineID},
	}
	fixNew := []db.Finding{{ID: 4, Fingerprint: "n", Title: "new medium", Severity: "Medium", ScanID: fixID}}
	verify := []fixValidationVerify{
		{FindingID: 3, Title: "resolved one", Status: "fixed"},
		{FindingID: 2, Title: "critical survivor", Status: "confirmed"},
	}

	rep := buildFixValidationReport(fixScan, baselineID, baseline, fixNew, []uint{1, 2}, verify)

	if rep.FixRef != "fix-branch" || rep.Skill != "security-deep-dive" ||
		rep.BaselineScanID != baselineID || rep.FixScanID != fixID || rep.FixCommit != "abc123" {
		t.Fatalf("metadata wrong: %+v", rep)
	}
	if (rep.Counts != fixValidationCounts{Resolved: 1, Surviving: 2, New: 1}) {
		t.Fatalf("counts = %+v, want {1 2 1}", rep.Counts)
	}
	// Surviving sorted severity high to low: Critical (id 2) before Low (id 1).
	if len(rep.Surviving) != 2 || rep.Surviving[0].FindingID != 2 || rep.Surviving[1].FindingID != 1 {
		t.Fatalf("surviving order = %+v, want [id2, id1]", rep.Surviving)
	}
	// Verify sorted by finding id ascending: 2 then 3.
	if len(rep.Verify) != 2 || rep.Verify[0].FindingID != 2 || rep.Verify[1].FindingID != 3 {
		t.Fatalf("verify order = %+v, want [id2, id3]", rep.Verify)
	}
}

func TestBuildFixValidationReport_emptyBucketsMarshalAsArrays(t *testing.T) {
	rep := buildFixValidationReport(db.Scan{ID: 20}, 10, nil, nil, nil, nil)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"resolved":[]`, `"surviving":[]`, `"new":[]`, `"verify":[]`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("empty report JSON missing %s:\n%s", want, b)
		}
	}
}

func TestBuildFixValidationReport_keepsFingerprintDiffSeparateFromVerification(t *testing.T) {
	for _, status := range []string{"unverified", "fixed"} {
		t.Run(status, func(t *testing.T) {
			scan := db.Scan{ID: 20, Commit: "candidate-commit"}
			baseline := []db.Finding{{ID: 1, ScanID: 10, LastSeenScanID: 10, Title: "missed finding"}}
			verify := []fixValidationVerify{{FindingID: 1, Status: status, ScanID: 30, Commit: scan.Commit}}
			raw, err := json.Marshal(buildFixValidationReport(scan, 10, baseline, nil, nil, verify))
			if err != nil {
				t.Fatal(err)
			}
			var report struct {
				Counts   map[string]int         `json:"counts"`
				Resolved []fixValidationFinding `json:"resolved"`
				Verify   []fixValidationVerify  `json:"verify"`
			}
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), `"not_seen"`) {
				t.Errorf("fingerprint bucket keys must remain compatible: %s", raw)
			}
			if report.Counts["resolved"] != 1 || len(report.Resolved) != 1 || report.Resolved[0].FindingID != 1 {
				t.Errorf("missing resolved observation: %s", raw)
			}
			if len(report.Verify) != 1 || report.Verify[0].Status != status {
				t.Errorf("verification must remain a separate result: %s", raw)
			}
		})
	}
}
