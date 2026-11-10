package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"scrutineer/internal/db"
	"scrutineer/internal/verification"
)

func TestFindingShowVerificationIdentifiesGradedRevision(t *testing.T) {
	const (
		commitA = "3091c393df64b9035f294197a208e5b7b3c53fa4"
		commitB = "5228d9bee88300b32c53c5ef403f43564d57e7a0"
	)
	for _, tc := range []struct {
		name   string
		commit string
		run    uint
		want   string
	}{
		{"graded at A, scan resumed at B", commitA, 1, "fixed at 3091c393df64"},
		{"legacy grade without provenance", "", 0, "fixed (commit not recorded)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			finding := seedFindingForForm(t, s)
			scan := db.Scan{RepositoryID: finding.RepositoryID, FindingID: &finding.ID,
				Kind: "skill", SkillName: verifySkillName, Status: db.ScanDone,
				Commit: commitB, RunNumber: 2}
			if err := s.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			report := revisionFixedReport("The checked code rejects index 8.")
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			score := report.Score()
			grade := db.FindingVerification{FindingID: finding.ID, ScanID: scan.ID,
				Commit: tc.commit, RunNumber: tc.run, Status: report.Status, Score: &score, Report: string(raw)}
			if err := s.DB.Create(&grade).Error; err != nil {
				t.Fatal(err)
			}

			body := pageBody(t, s, fmt.Sprintf("/findings/%d", finding.ID))
			doc, err := html.Parse(strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			var text strings.Builder
			walkHTML(doc, func(n *html.Node) {
				if n.Type == html.TextNode {
					text.WriteString(n.Data)
					text.WriteByte(' ')
				}
			})
			visible := strings.Join(strings.Fields(text.String()), " ")
			if count := strings.Count(visible, tc.want); count != 2 {
				t.Errorf("summary and history show %q %d times, want 2", tc.want, count)
			}
			if strings.Contains(visible, commitB[:12]) || strings.Contains(visible, "run 2") {
				t.Error("verification display borrowed provenance from the resumed scan at B")
			}
			if tc.run > 0 && strings.Count(visible, "run 1") != 2 {
				t.Error("summary and history do not identify the graded run")
			}
		})
	}
}

func TestLoadFindingVerificationViewsToleratesUngradedRow(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: verifySkillName}
	s.DB.Create(&scan)
	ungradedScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: verifySkillName}
	s.DB.Create(&ungradedScan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "graded", Severity: "High"}
	s.DB.Create(&finding)

	report := completeVerificationReport()
	report.Criteria.ControlBypass.UnavailableReason = "the repository threat model could not be read"
	validReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	score := report.Score()
	graded := db.FindingVerification{
		FindingID: finding.ID,
		ScanID:    scan.ID,
		Status:    report.Status,
		Score:     &score,
		Report:    string(validReport),
	}
	if err := s.DB.Create(&graded).Error; err != nil {
		t.Fatal(err)
	}

	report.Attempts[1].Number = report.Attempts[0].Number
	invalidReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	ungraded := db.FindingVerification{
		FindingID: finding.ID,
		ScanID:    ungradedScan.ID,
		Status:    report.Status,
		Report:    string(invalidReport),
	}
	if err := s.DB.Create(&ungraded).Error; err != nil {
		t.Fatal(err)
	}

	views, err := loadFindingVerificationViews(s.DB, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 {
		t.Fatalf("views = %d, want 2", len(views))
	}
	if views[0].ID != ungraded.ID || views[0].ScoreLabel != "ungraded" || views[0].HasRubric {
		t.Errorf("ungraded view = %+v", views[0])
	}
	if views[1].ID != graded.ID || views[1].ScoreLabel != "100%" || !views[1].HasRubric {
		t.Errorf("graded view = %+v", views[1])
	}
	if views[1].ControlBypass == nil || views[1].ControlBypass.UnavailableReason != report.Criteria.ControlBypass.UnavailableReason {
		t.Errorf("graded control bypass = %+v, want unavailable reason", views[1].ControlBypass)
	}
	if len(views[1].Prerequisites) != 5 || views[1].Prerequisites[0].Assessment.Value != "remote_unauthenticated" {
		t.Errorf("graded prerequisites = %+v", views[1].Prerequisites)
	}
}

func completeVerificationReport() verification.Report {
	criterion := verification.Criterion{
		Verdict:    "pass",
		Method:     "run",
		Evidence:   "observed",
		Confidence: "high",
	}
	root := "AT1"
	entryPoint := "AT2"
	return verification.Report{
		Status: "confirmed",
		AttackTree: &verification.AttackTree{
			Goal:    "Trigger parser panic",
			RootID:  root,
			Verdict: "reachable",
			Nodes: []verification.AttackTreeNode{
				{ID: root, Kind: "goal", Description: "Trigger parser panic", Status: "satisfied", Evidence: "3/3 attempts panic"},
				{ID: entryPoint, ParentID: &root, Kind: "entry_point", Description: "Call public Parse", Status: "satisfied", Evidence: "api.go:18"},
				{ID: "AT3", ParentID: &entryPoint, Kind: "sink", Description: "Reach parser sink", Status: "satisfied", Evidence: "parser.go:42"},
			},
			Blockers: []string{},
		},
		SeverityPrerequisites: &verification.SeverityPrerequisites{
			AttackerPosition:   verification.PrerequisiteValue{Value: "remote_unauthenticated", Evidence: "public API accepts remote input"},
			UserInteraction:    verification.PrerequisiteValue{Value: "none", Evidence: "request processing needs no victim action"},
			OutcomeDeterminism: verification.PrerequisiteValue{Value: "deterministic", Evidence: "3/3 attempts reach the same sink"},
			Impact:             verification.PrerequisiteValue{Value: "code_execution_or_equivalent", Evidence: "attempts execute attacker-controlled code"},
			ExistingCapability: verification.PrerequisiteValue{Value: "none", Evidence: "attacker starts without host access"},
		},
		Attempts: []verification.Attempt{
			{Number: 1, Outcome: "reproduced", Evidence: "same panic", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 2, Outcome: "reproduced", Evidence: "same panic", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 3, Outcome: "reproduced", Evidence: "same panic", FailureClass: "panic", CrashSite: "parser.go:42"},
		},
		Criteria: &verification.Criteria{
			PoCWellFormed:                   criterion,
			ReproducesThreeOfThree:          criterion,
			ClaimedFailureClass:             criterion,
			PublicInterfaceToFirstPartySink: criterion,
			Deterministic:                   criterion,
			ControlBypass: &verification.ControlBypass{
				MatchedControls: []string{},
				Assessments:     []verification.ControlAssessment{},
			},
		},
	}
}
