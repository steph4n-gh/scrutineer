package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

type validateFixFixture struct {
	s          *Server
	repoID     uint
	baselineID uint
	deepDiveID uint
	verifyID   uint
	f1, f2     db.Finding
}

// validateFixSetup builds a repo with an active deep-dive and verify skill, a
// done baseline deep-dive scan, and two findings under it — the starting state
// a fix-validation run acts on.
func validateFixSetup(t *testing.T) (validateFixFixture, func()) {
	t.Helper()
	s, done := newTestServer(t)
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	deepdive := db.Skill{Name: deepDiveSkillName, OutputFile: "report.json", OutputKind: "findings", Version: 1, Active: true}
	verify := db.Skill{Name: verifySkillName, OutputFile: "report.json", OutputKind: "verify", Version: 1, Active: true}
	s.DB.Create(&deepdive)
	s.DB.Create(&verify)
	baseline := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillID: &deepdive.ID, SkillName: deepDiveSkillName}
	s.DB.Create(&baseline)
	f1 := db.Finding{ScanID: baseline.ID, RepositoryID: repo.ID, Title: "f1", Severity: "High", Fingerprint: "fp1", Status: db.FindingNew}
	f2 := db.Finding{ScanID: baseline.ID, RepositoryID: repo.ID, Title: "f2", Severity: "Critical", Fingerprint: "fp2", Status: db.FindingNew}
	s.DB.Create(&f1)
	s.DB.Create(&f2)
	return validateFixFixture{s, repo.ID, baseline.ID, deepdive.ID, verify.ID, f1, f2}, done
}

func validateFixPost(s *Server, repoID uint, ref string, findingIDs ...uint) *httptest.ResponseRecorder {
	form := url.Values{}
	if ref != "" {
		form.Set("ref", ref)
	}
	for _, id := range findingIDs {
		form.Add("finding_ids", strconv.FormatUint(uint64(id), 10))
	}
	r := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/validate-fix", repoID), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	asOperator(r)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func validationAnchorCount(s *Server) int64 {
	var n int64
	s.DB.Model(&db.Scan{}).Where("baseline_scan_id IS NOT NULL").Count(&n)
	return n
}

func TestValidateFix_happy(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()

	w := validateFixPost(fx.s, fx.repoID, "fix-branch", fx.f1.ID, fx.f2.ID)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body.String())
	}
	var anchor db.Scan
	if err := fx.s.DB.Where("repository_id = ? AND baseline_scan_id = ? AND ref = ?",
		fx.repoID, fx.baselineID, "fix-branch").First(&anchor).Error; err != nil {
		t.Fatalf("anchor scan not created: %v", err)
	}
	if anchor.SkillID == nil || *anchor.SkillID != fx.deepDiveID {
		t.Fatalf("anchor skill = %v, want deep-dive %d", anchor.SkillID, fx.deepDiveID)
	}
	if loc := w.Header().Get("Location"); loc != fmt.Sprintf("/scans/%d", anchor.ID) {
		t.Fatalf("redirect = %q, want /scans/%d", loc, anchor.ID)
	}
	var verifyCount int64
	fx.s.DB.Model(&db.Scan{}).
		Where("skill_id = ? AND ref = ? AND finding_id IN ?", fx.verifyID, "fix-branch", []uint{fx.f1.ID, fx.f2.ID}).
		Count(&verifyCount)
	if verifyCount != 2 {
		t.Fatalf("verify-against-ref scans = %d, want 2", verifyCount)
	}
}

func TestValidateFix_rejects(t *testing.T) {
	t.Run("missing ref", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		w := validateFixPost(fx.s, fx.repoID, "", fx.f1.ID)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("invalid ref", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		w := validateFixPost(fx.s, fx.repoID, "--bad ref", fx.f1.ID)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("no finding ids", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		w := validateFixPost(fx.s, fx.repoID, "fix-branch")
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("finding not on repo", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		w := validateFixPost(fx.s, fx.repoID, "fix-branch", fx.f1.ID, 999999)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("findings from different scans", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		other := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillID: &fx.deepDiveID, SkillName: deepDiveSkillName}
		fx.s.DB.Create(&other)
		stray := db.Finding{ScanID: other.ID, RepositoryID: fx.repoID, Title: "stray", Severity: "Low", Fingerprint: "fpx"}
		fx.s.DB.Create(&stray)
		w := validateFixPost(fx.s, fx.repoID, "fix-branch", fx.f1.ID, stray.ID)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("baseline scan has no skill", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		noSkill := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: "import"}
		fx.s.DB.Create(&noSkill)
		imported := db.Finding{ScanID: noSkill.ID, RepositoryID: fx.repoID, Title: "imp", Severity: "Low", Fingerprint: "fpi"}
		fx.s.DB.Create(&imported)
		w := validateFixPost(fx.s, fx.repoID, "fix-branch", imported.ID)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
}

func assertValidateFixRejected(t *testing.T, s *Server, w *httptest.ResponseRecorder, repoID uint) {
	t.Helper()
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 redirect; body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != fmt.Sprintf("/repositories/%d", repoID) {
		t.Fatalf("redirect = %q, want repo page /repositories/%d", loc, repoID)
	}
	if n := validationAnchorCount(s); n != 0 {
		t.Fatalf("rejected request still created %d anchor scan(s)", n)
	}
}

func TestAutoComputeFixValidation_writesReport(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()

	anchor := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: deepDiveSkillName, Ref: "fix", Commit: "abc123", BaselineScanID: &fx.baselineID}
	fx.s.DB.Create(&anchor)
	// f1 survived (re-observed by the anchor), f2 not seen (not re-observed).
	if err := db.RecordFindingObservation(fx.s.DB, db.ObservationFromFinding(&anchor, &fx.f1)); err != nil {
		t.Fatal(err)
	}
	fx.s.DB.Model(&db.Finding{}).Where("id = ?", fx.f1.ID).Update("last_seen_scan_id", anchor.ID)
	fx.s.DB.Model(&db.Finding{}).Where("id = ?", fx.f2.ID).Update("last_seen_scan_id", fx.baselineID)
	newF := db.Finding{ScanID: anchor.ID, RepositoryID: fx.repoID, Title: "new on fix ref", Severity: "Medium", Fingerprint: "fpnew"}
	fx.s.DB.Create(&newF)
	if err := db.RecordFindingObservation(fx.s.DB, db.ObservationFromFinding(&anchor, &newF)); err != nil {
		t.Fatal(err)
	}
	verifyScan := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: verifySkillName, RunNumber: 1, Ref: "fix", Commit: anchor.Commit, FindingID: &fx.f1.ID, Report: `{"status":"confirmed"}`}
	fx.s.DB.Create(&verifyScan)
	score := 1.0
	if err := fx.s.DB.Create(&db.FindingVerification{Commit: verifyScan.Commit, RunNumber: 1, ScanID: verifyScan.ID, FindingID: fx.f1.ID, Status: "confirmed", Score: &score, Report: verifyScan.Report}).Error; err != nil {
		t.Fatal(err)
	}

	fx.s.autoComputeFixValidation(&anchor)

	var reloaded db.Scan
	fx.s.DB.First(&reloaded, anchor.ID)
	var rep fixValidationReport
	if err := json.Unmarshal([]byte(reloaded.Report), &rep); err != nil {
		t.Fatalf("report is not valid JSON: %v; report=%q", err, reloaded.Report)
	}
	if (rep.Counts != fixValidationCounts{Resolved: 1, Surviving: 1, New: 1}) {
		t.Fatalf("counts = %+v, want {1 1 1}", rep.Counts)
	}
	if len(rep.Resolved) != 1 || rep.Resolved[0].FindingID != fx.f2.ID {
		t.Fatalf("resolved = %+v, want [f2 id=%d]", rep.Resolved, fx.f2.ID)
	}
	if len(rep.Surviving) != 1 || rep.Surviving[0].FindingID != fx.f1.ID {
		t.Fatalf("surviving = %+v, want [f1 id=%d]", rep.Surviving, fx.f1.ID)
	}
	if len(rep.Verify) != 1 || rep.Verify[0].FindingID != fx.f1.ID || rep.Verify[0].Status != "confirmed" {
		t.Fatalf("verify = %+v, want [f1 confirmed]", rep.Verify)
	}
}

func TestAutoComputeFixValidation_pendingVerify(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()
	anchor := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: deepDiveSkillName, Ref: "fix", BaselineScanID: &fx.baselineID}
	fx.s.DB.Create(&anchor)
	// A verify against the fix ref that has not finished yet.
	verifyScan := db.Scan{RepositoryID: fx.repoID, Status: db.ScanRunning, SkillName: verifySkillName, RunNumber: 1, Ref: "fix", FindingID: &fx.f1.ID}
	fx.s.DB.Create(&verifyScan)

	fx.s.autoComputeFixValidation(&anchor)

	var reloaded db.Scan
	fx.s.DB.First(&reloaded, anchor.ID)
	var rep fixValidationReport
	if err := json.Unmarshal([]byte(reloaded.Report), &rep); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if len(rep.Verify) != 1 || rep.Verify[0].Status != verifyStatusPending {
		t.Fatalf("verify = %+v, want [f1 pending]", rep.Verify)
	}
}

type fixValidationCommitCase struct {
	name         string
	anchorCommit string
	verifyCommit string
	scanStatus   db.ScanStatus
	verdict      string
	wantStatus   string
}

func TestAutoComputeFixValidation_requiresMatchingCommit(t *testing.T) {
	const commitA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const commitB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []fixValidationCommitCase{
		{"branch advanced", commitB, commitA, db.ScanDone, "fixed", "unverified"},
		{"older failure", commitB, commitA, db.ScanDone, "confirmed", "unverified"},
		{"same commit", commitA, commitA, db.ScanDone, "fixed", "fixed"},
		{"unknown verify commit", commitB, "", db.ScanDone, "fixed", "unverified"},
		{"unknown anchor commit", "", commitA, db.ScanDone, "fixed", "unverified"},
		{"both commits unknown", "", "", db.ScanDone, "fixed", "unverified"},
		{"latest still running", commitB, "", db.ScanRunning, "fixed", "pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkFixValidationCommit(t, tc)
		})
	}
}

func checkFixValidationCommit(t *testing.T, tc fixValidationCommitCase) {
	t.Helper()
	fx, done := validateFixSetup(t)
	defer done()
	anchor := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: deepDiveSkillName,
		Ref: "candidate", Commit: tc.anchorCommit, BaselineScanID: &fx.baselineID}
	if err := fx.s.DB.Create(&anchor).Error; err != nil {
		t.Fatal(err)
	}
	// The latest attempt must not fall back to an older matching verdict.
	older := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: verifySkillName, RunNumber: 1,
		Ref: "candidate", Commit: tc.anchorCommit, FindingID: &fx.f1.ID, Report: `{"status":"confirmed"}`}
	if err := fx.s.DB.Create(&older).Error; err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{"status": tc.verdict})
	if err != nil {
		t.Fatal(err)
	}
	verify := db.Scan{RepositoryID: fx.repoID, Status: tc.scanStatus, SkillName: verifySkillName, RunNumber: 1,
		Ref: "candidate", Commit: tc.verifyCommit, FindingID: &fx.f1.ID, Report: string(raw)}
	if err := fx.s.DB.Create(&verify).Error; err != nil {
		t.Fatal(err)
	}
	score := 1.0
	for _, scan := range []db.Scan{older, verify} {
		if scan.Status != db.ScanDone {
			continue
		}
		status := tc.verdict
		if scan.ID == older.ID {
			status = "confirmed"
		}
		if err := fx.s.DB.Create(&db.FindingVerification{Commit: scan.Commit, RunNumber: 1, ScanID: scan.ID, FindingID: fx.f1.ID, Status: status, Score: &score, Report: scan.Report}).Error; err != nil {
			t.Fatal(err)
		}
	}

	fx.s.autoComputeFixValidation(&anchor)

	var saved db.Scan
	if err := fx.s.DB.First(&saved, anchor.ID).Error; err != nil {
		t.Fatal(err)
	}
	var report struct {
		FixCommit string `json:"fix_commit"`
		Verify    []struct {
			FindingID uint   `json:"finding_id"`
			Status    string `json:"status"`
			ScanID    uint   `json:"verify_scan_id"`
			Commit    string `json:"verify_commit"`
		} `json:"verify"`
	}
	if err := json.Unmarshal([]byte(saved.Report), &report); err != nil {
		t.Fatal(err)
	}
	if report.FixCommit != tc.anchorCommit || len(report.Verify) != 1 {
		t.Fatalf("unexpected report: %s", saved.Report)
	}
	v := report.Verify[0]
	if v.Status != tc.wantStatus {
		t.Errorf("status = %q, want %q; anchor commit %q, verify commit %q", v.Status, tc.wantStatus, tc.anchorCommit, tc.verifyCommit)
	}
	if v.FindingID != fx.f1.ID || v.ScanID != verify.ID || v.Commit != tc.verifyCommit {
		t.Errorf("verification provenance = %+v, want finding %d, scan %d, commit %q", v, fx.f1.ID, verify.ID, tc.verifyCommit)
	}
}

func TestAutoComputeFixValidation_ignoresOrdinaryScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: deepDiveSkillName, Report: "untouched"}
	s.DB.Create(&scan)
	s.autoComputeFixValidation(&scan)
	var reloaded db.Scan
	s.DB.First(&reloaded, scan.ID)
	if reloaded.Report != "untouched" {
		t.Fatalf("ordinary scan report changed to %q", reloaded.Report)
	}
}

func TestAutoComputeFixValidation_nilScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.autoComputeFixValidation(nil)
}

// TestFixValidationAnchor_skipsAutoFunnel proves a validation anchor (a
// deep-dive re-run carrying BaselineScanID) does not feed its findings back
// into the revalidate or finding-dedup auto-funnel.
func TestFixValidationAnchor_skipsAutoFunnel(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()
	dedup := db.Skill{Name: findingDedupSkillName, OutputFile: "report.json", OutputKind: "finding_dedup", Version: 1, Active: true}
	reval := db.Skill{Name: revalidateSkillName, OutputFile: "report.json", OutputKind: "revalidate", Version: 1, Active: true}
	fx.s.DB.Create(&dedup)
	fx.s.DB.Create(&reval)

	anchor := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: deepDiveSkillName, Ref: "fix", BaselineScanID: &fx.baselineID}
	fx.s.DB.Create(&anchor)
	anchorFinding := db.Finding{ScanID: anchor.ID, RepositoryID: fx.repoID, Title: "anchor finding", Severity: "Critical", Fingerprint: "afp"}
	fx.s.DB.Create(&anchorFinding)

	fx.s.autoEnqueueRevalidate(&anchor, &anchorFinding)
	fx.s.onScanFinalized(&anchor)

	var revalQ, dedupQ int64
	fx.s.DB.Model(&db.Scan{}).Where("skill_id = ? AND status = ?", reval.ID, db.ScanQueued).Count(&revalQ)
	fx.s.DB.Model(&db.Scan{}).Where("skill_id = ? AND status = ?", dedup.ID, db.ScanQueued).Count(&dedupQ)
	if revalQ != 0 || dedupQ != 0 {
		t.Fatalf("anchor scan triggered the auto-funnel: revalidate=%d dedup=%d, want 0/0", revalQ, dedupQ)
	}
}

func TestParseFindingIDs(t *testing.T) {
	form := func(values ...string) *http.Request {
		v := url.Values{}
		for _, val := range values {
			v.Add("finding_ids", val)
		}
		r := httptest.NewRequest("POST", "/x", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	got, err := parseFindingIDs(form("3", "1,2", "3"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 || got[0] != 3 || got[1] != 1 || got[2] != 2 {
		t.Fatalf("ids = %v, want [3 1 2] (split, de-duped, order-preserving)", got)
	}
	if _, err := parseFindingIDs(form()); err == nil {
		t.Fatal("empty finding_ids: expected error")
	}
	if _, err := parseFindingIDs(form("notanumber")); err == nil {
		t.Fatal("non-numeric finding id: expected error")
	}
}

// Realize the database interleaving after the anchor observes f1 and before
// its report is assembled. This is deterministic; it does not race workers.
func TestAutoComputeFixValidation_keepsAnchorObservation(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()
	anchor := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: deepDiveSkillName,
		Ref: "candidate", Commit: "B", BaselineScanID: &fx.baselineID}
	sibling := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: deepDiveSkillName,
		Ref: "main", Commit: "C"}
	for _, scan := range []*db.Scan{&anchor, &sibling} {
		if err := fx.s.DB.Create(scan).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.RecordFindingObservation(fx.s.DB, db.ObservationFromFinding(scan, &fx.f1)); err != nil {
			t.Fatal(err)
		}
		if err := fx.s.DB.Model(&db.Finding{}).Where("id = ?", fx.f1.ID).Update("last_seen_scan_id", scan.ID).Error; err != nil {
			t.Fatal(err)
		}
	}
	// A sibling-only observation of f2 must not count for this anchor.
	if err := db.RecordFindingObservation(fx.s.DB, db.ObservationFromFinding(&sibling, &fx.f2)); err != nil {
		t.Fatal(err)
	}
	fx.s.autoComputeFixValidation(&anchor)
	var saved db.Scan
	if err := fx.s.DB.First(&saved, anchor.ID).Error; err != nil {
		t.Fatal(err)
	}
	t.Logf("OBSERVATION_REPORT %s", saved.Report)
	var report fixValidationReport
	if err := json.Unmarshal([]byte(saved.Report), &report); err != nil {
		t.Fatal(err)
	}
	if report.Counts.Surviving != 1 || len(report.Surviving) != 1 || report.Surviving[0].FindingID != fx.f1.ID {
		t.Errorf("anchor observation lost after another scan: %s", saved.Report)
	}
	if report.Counts.Resolved != 1 || len(report.Resolved) != 1 || report.Resolved[0].FindingID != fx.f2.ID {
		t.Errorf("sibling-only finding must remain resolved: %s", saved.Report)
	}
}

func TestFixValidationVerdicts_requiresAcceptedGrading(t *testing.T) {
	zero := 0.0
	for _, tc := range []struct {
		name                 string
		hasGrade             bool
		score                *float64
		gradedStatus         string
		maxTurns, costCapped bool
		want                 string
	}{
		{name: "missing grading record", want: "unverified"},
		{name: "rejected grading", hasGrade: true, gradedStatus: "fixed", want: "unverified"},
		{name: "accepted zero score", hasGrade: true, score: &zero, gradedStatus: "fixed", want: "fixed"},
		{name: "accepted verdict instead of raw status", hasGrade: true, score: &zero, gradedStatus: "confirmed", want: "confirmed"},
		{name: "turn-limited", hasGrade: true, score: &zero, gradedStatus: "fixed", maxTurns: true, want: "unverified"},
		{name: "cost-capped", hasGrade: true, score: &zero, gradedStatus: "fixed", costCapped: true, want: "unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx, done := validateFixSetup(t)
			defer done()
			older := db.Scan{RepositoryID: fx.repoID, FindingID: &fx.f1.ID, SkillName: verifySkillName, RunNumber: 1,
				Ref: "candidate", Commit: "same", Status: db.ScanDone, Report: `{"status":"fixed"}`}
			if err := fx.s.DB.Create(&older).Error; err != nil {
				t.Fatal(err)
			}
			if err := fx.s.DB.Create(&db.FindingVerification{Commit: older.Commit, RunNumber: 1, ScanID: older.ID, FindingID: fx.f1.ID, Status: "fixed", Score: &zero, Report: older.Report}).Error; err != nil {
				t.Fatal(err)
			}
			latest := db.Scan{RepositoryID: fx.repoID, FindingID: &fx.f1.ID, SkillName: verifySkillName, RunNumber: 1,
				Ref: "candidate", Commit: "same", Status: db.ScanDone, Report: `{"status":"fixed"}`,
				MaxTurnsHit: tc.maxTurns, CostCapped: tc.costCapped}
			if err := fx.s.DB.Create(&latest).Error; err != nil {
				t.Fatal(err)
			}
			if tc.hasGrade {
				// Constructed record: the disagreement case checks which source wins.
				if err := fx.s.DB.Create(&db.FindingVerification{Commit: latest.Commit, RunNumber: 1, ScanID: latest.ID, FindingID: fx.f1.ID, Status: tc.gradedStatus, Score: tc.score, Report: latest.Report}).Error; err != nil {
					t.Fatal(err)
				}
			}
			got := fx.s.fixValidationVerdicts([]db.Finding{fx.f1}, "candidate", "same")
			if len(got) != 1 || got[0].ScanID != latest.ID || got[0].Status != tc.want {
				t.Fatalf("verdict = %+v, want latest scan %d status %s", got, latest.ID, tc.want)
			}
		})
	}
}

func TestFixValidationVerdicts_requiresMatchingExecution(t *testing.T) {
	for _, tc := range []struct {
		name              string
		scanRun, gradeRun uint
		gradeCommit, want string
	}{
		{"matching execution", 1, 1, "current", "fixed"},
		{"prior execution", 2, 1, "current", "unverified"},
		{"unknown execution", 0, 0, "current", "unverified"},
		{"prior commit", 1, 1, "older", "unverified"},
		{"unknown grading commit", 1, 1, "", "unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx, done := validateFixSetup(t)
			defer done()
			scan := db.Scan{RepositoryID: fx.repoID, FindingID: &fx.f1.ID, SkillName: verifySkillName,
				Ref: "candidate", Commit: "current", RunNumber: tc.scanRun, Status: db.ScanDone}
			if err := fx.s.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			score := 0.0
			grade := db.FindingVerification{ScanID: scan.ID, FindingID: fx.f1.ID, Commit: tc.gradeCommit,
				RunNumber: tc.gradeRun, Status: "fixed", Score: &score, Report: `{"status":"fixed"}`}
			if err := fx.s.DB.Create(&grade).Error; err != nil {
				t.Fatal(err)
			}
			got := fx.s.fixValidationVerdicts([]db.Finding{fx.f1}, "candidate", "current")
			if len(got) != 1 || got[0].Status != tc.want {
				t.Fatalf("verdict=%+v, want %s", got, tc.want)
			}
		})
	}
}

// Deliberately construct a wrong-subject row to test the batched subject guard.
func TestFixValidationVerdicts_keepsGradingSubjectsSeparate(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()
	f1Scan := db.Scan{RepositoryID: fx.repoID, FindingID: &fx.f1.ID, SkillName: verifySkillName,
		Ref: "candidate", Commit: "current", RunNumber: 1, Status: db.ScanDone}
	f2Scan := f1Scan
	f2Scan.FindingID = &fx.f2.ID
	for _, scan := range []*db.Scan{&f1Scan, &f2Scan} {
		if err := fx.s.DB.Create(scan).Error; err != nil {
			t.Fatal(err)
		}
	}
	score := 0.0
	for _, grade := range []db.FindingVerification{
		{ScanID: f1Scan.ID, FindingID: fx.f1.ID, Commit: "current", RunNumber: 1, Status: "fixed", Score: &score},
		{ScanID: f2Scan.ID, FindingID: fx.f2.ID, Commit: "current", RunNumber: 1, Status: "fixed"},
		{ScanID: f2Scan.ID, FindingID: fx.f1.ID, Commit: "current", RunNumber: 1, Status: "fixed", Score: &score},
	} {
		if err := fx.s.DB.Create(&grade).Error; err != nil {
			t.Fatal(err)
		}
	}
	got := fx.s.fixValidationVerdicts([]db.Finding{fx.f1, fx.f2}, "candidate", "current")
	if len(got) != 2 {
		t.Fatalf("verdicts=%+v, want two findings", got)
	}
	for _, v := range got {
		want := "unverified"
		if v.FindingID == fx.f1.ID {
			want = "fixed"
		}
		if v.Status != want {
			t.Fatalf("verdicts=%+v, finding %d wants %s", got, v.FindingID, want)
		}
	}
}

func TestAutoComputeFixValidation_ignoresPriorRevisionObservation(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()
	anchor := db.Scan{RepositoryID: fx.repoID, SkillName: deepDiveSkillName, Status: db.ScanDone,
		Commit: "B", Ref: "candidate", BaselineScanID: &fx.baselineID}
	if err := fx.s.DB.Create(&anchor).Error; err != nil {
		t.Fatal(err)
	}
	prior := anchor
	prior.Commit = "A"
	if err := db.RecordFindingObservation(fx.s.DB, db.ObservationFromFinding(&prior, &fx.f1)); err != nil {
		t.Fatal(err)
	}
	fx.s.autoComputeFixValidation(&anchor)
	var saved db.Scan
	if err := fx.s.DB.First(&saved, anchor.ID).Error; err != nil {
		t.Fatal(err)
	}
	var report fixValidationReport
	if err := json.Unmarshal([]byte(saved.Report), &report); err != nil {
		t.Fatal(err)
	}
	if report.Counts.Surviving != 0 || report.Counts.Resolved != 2 {
		t.Fatalf("prior revision observation applied to B: %s", saved.Report)
	}
}

func TestAutoComputeFixValidation_newFindingsMatchAnchorRevision(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()
	anchor := db.Scan{RepositoryID: fx.repoID, SkillName: deepDiveSkillName, Status: db.ScanDone,
		Commit: "B", Ref: "candidate", BaselineScanID: &fx.baselineID}
	if err := fx.s.DB.Create(&anchor).Error; err != nil {
		t.Fatal(err)
	}
	stale := db.Finding{ScanID: anchor.ID, RepositoryID: fx.repoID, Commit: "A", Title: "only at A", Fingerprint: "new-stale"}
	reobserved := db.Finding{ScanID: anchor.ID, RepositoryID: fx.repoID, Commit: "A", Title: "also at B", Fingerprint: "new-reobserved"}
	fresh := db.Finding{ScanID: anchor.ID, RepositoryID: fx.repoID, Commit: "B", Title: "first at B", Fingerprint: "new-fresh"}
	prior := anchor
	prior.Commit = "A"
	for _, f := range []*db.Finding{&stale, &reobserved, &fresh} {
		if err := fx.s.DB.Create(f).Error; err != nil {
			t.Fatal(err)
		}
		scan := &prior
		if f == &fresh {
			scan = &anchor
		}
		if err := db.RecordFindingObservation(fx.s.DB, db.ObservationFromFinding(scan, f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RecordFindingObservation(fx.s.DB, db.ObservationFromFinding(&anchor, &reobserved)); err != nil {
		t.Fatal(err)
	}
	fx.s.autoComputeFixValidation(&anchor)
	var saved db.Scan
	if err := fx.s.DB.First(&saved, anchor.ID).Error; err != nil {
		t.Fatal(err)
	}
	t.Logf("NEW_FINDINGS_REPORT %s", saved.Report)
	var report fixValidationReport
	if err := json.Unmarshal([]byte(saved.Report), &report); err != nil {
		t.Fatal(err)
	}
	if report.Counts.New != 2 || len(report.New) != 2 {
		t.Fatalf("stale A finding reported at B: %s", saved.Report)
	}
	for _, f := range report.New {
		if f.FindingID != reobserved.ID && f.FindingID != fresh.ID {
			t.Fatalf("wrong new finding at B: %+v", f)
		}
	}
}
