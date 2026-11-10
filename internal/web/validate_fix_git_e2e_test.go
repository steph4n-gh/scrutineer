package web

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/testutil"
	"scrutineer/internal/verification"
	"scrutineer/internal/worker"
)

const revisionTarget = `package main
import ("fmt"; "os"; "strconv")
func accepts(index int) bool { return index >= 0 && index BOUND 8 }
func main() {
 index, err := strconv.Atoi(os.Args[1]); if err != nil { panic(err) }
 accepted := accepts(index)
 fmt.Printf("index=%d accepted=%t\n", index, accepted)
 if index == 8 && accepted { os.Exit(23) }
 if index == 7 && !accepted { os.Exit(24) }
}
`

func revisionGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(testutil.GitEnv(), "GIT_ALLOW_PROTOCOL=file:https")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %v: %w: %s", args, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// revisionProbeRunner replaces only the analysis backend. It builds and runs
// the code the real worker cloned, and derives reports from its exit status.
type revisionProbeRunner struct {
	advance        func(context.Context) error
	missRescan     bool
	ungradedVerify bool
	resumeVerify   bool
	verifyRuns     *atomic.Uint32
}

func (revisionProbeRunner) SkillDir(root, name string) string {
	return filepath.Join(root, "skills", name)
}

func (r revisionProbeRunner) RunSkill(ctx context.Context, job worker.SkillJob, emit func(worker.Event)) (worker.SkillResult, error) {
	src := filepath.Join(job.WorkRoot, "src")
	commit, err := revisionGit(ctx, src, "rev-parse", "HEAD")
	if err != nil {
		return worker.SkillResult{}, err
	}
	binary := filepath.Join(job.WorkRoot, "revision-target")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "main.go")
	build.Dir = src
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		return worker.SkillResult{}, fmt.Errorf("build target: %w: %s", err, out)
	}
	emit(worker.Event{Kind: worker.KindText, Text: fmt.Sprintf("REAL_CHECKOUT skill=%s commit=%s", job.Name, commit)})
	control, err := exec.CommandContext(ctx, binary, "7").CombinedOutput()
	if err != nil {
		return worker.SkillResult{}, fmt.Errorf("positive control: %w: %s", err, control)
	}
	emit(worker.Event{Kind: worker.KindText, Text: "CONTROL " + strings.TrimSpace(string(control))})
	attempts := 1
	if job.Name == verifySkillName {
		attempts = 3
	}
	var evidence []string
	var reproduced bool
	for i := range attempts {
		out, probeErr := exec.CommandContext(ctx, binary, "8").CombinedOutput()
		if probeErr != nil {
			exit, ok := probeErr.(*exec.ExitError)
			if !ok || exit.ExitCode() != 23 {
				return worker.SkillResult{}, fmt.Errorf("boundary probe: %w: %s", probeErr, out)
			}
		}
		reproduced = probeErr != nil
		line := fmt.Sprintf("attempt=%d %s", i+1, strings.TrimSpace(string(out)))
		evidence = append(evidence, line)
		emit(worker.Event{Kind: worker.KindText, Text: "BOUNDARY " + line})
	}
	result := worker.SkillResult{} // Let the worker record the checkout commit.
	if job.Name == verifySkillName {
		run := r.verifyRuns.Add(1)
		if reproduced && !r.resumeVerify {
			return result, fmt.Errorf("scenario requires the verification checkout to contain fix A")
		}
		report, err := revisionVerificationReport(reproduced, strings.Join(evidence, "; "))
		if err != nil {
			return result, err
		}
		if r.ungradedVerify && (!r.resumeVerify || run > 1) {
			report.SeverityPrerequisites = nil
			emit(worker.Event{Kind: worker.KindText, Text: "UNGRADED_VERIFY: required severity_prerequisites deliberately omitted"})
		}
		raw, err := json.Marshal(report)
		if err != nil {
			return result, err
		}
		result.Report = string(raw)
		if err := r.advance(ctx); err != nil {
			return result, err
		}
		return result, nil
	}
	result.Report = `{"findings":[]}`
	if reproduced && r.missRescan && job.Ref == "candidate" {
		emit(worker.Event{Kind: worker.KindText, Text: "SIMULATED_RESCAN_MISS: the compiled code reproduced the bug, but the analysis report deliberately omits the finding"})
		return result, nil
	}
	if reproduced {
		result.Report = `{"findings":[{"id":"F1","title":"Capacity eight accepts index eight","severity":"Medium","confidence":"high","cwe":"CWE-193","location":"main.go:3","trace":"accepts(8) returns true for capacity 8","validation":"The compiled target accepts index 8 and exits 23."}]}`
	}
	return result, nil
}

func revisionFixedReport(evidence string) verification.Report {
	pass := verification.Criterion{Verdict: "pass", Method: "run", Evidence: evidence, Confidence: "high"}
	fail := pass
	fail.Verdict = "fail"
	return verification.Report{
		Status: "fixed", Evidence: evidence,
		AttackTree: &verification.AttackTree{
			Goal: "Accept index eight for capacity eight", RootID: "boundary", Verdict: "blocked",
			Nodes:    []verification.AttackTreeNode{{ID: "boundary", Kind: "goal", Description: "Accept the out-of-range index", Status: "blocked", Evidence: evidence}},
			Blockers: []string{"The checked code rejects index 8."},
		},
		SeverityPrerequisites: &verification.SeverityPrerequisites{
			AttackerPosition:   verification.PrerequisiteValue{Value: "local", Evidence: "Local fixture executable."},
			UserInteraction:    verification.PrerequisiteValue{Value: "none", Evidence: "Command-line reproduction."},
			OutcomeDeterminism: verification.PrerequisiteValue{Value: "deterministic", Evidence: evidence},
			Impact:             verification.PrerequisiteValue{Value: "other", Evidence: "Fixture demonstrates a bounds-check error only."},
			ExistingCapability: verification.PrerequisiteValue{Value: "none", Evidence: "Only an index is supplied."},
		},
		Attempts: []verification.Attempt{
			{Number: 1, Outcome: "not_reproduced", Evidence: evidence},
			{Number: 2, Outcome: "not_reproduced", Evidence: evidence},
			{Number: 3, Outcome: "not_reproduced", Evidence: evidence},
		},
		Criteria: &verification.Criteria{
			PoCWellFormed: pass, ReproducesThreeOfThree: fail, ClaimedFailureClass: fail,
			PublicInterfaceToFirstPartySink: fail, Deterministic: pass,
			ControlBypass: &verification.ControlBypass{MatchedControls: []string{}, Assessments: []verification.ControlAssessment{}},
		},
	}
}

func TestValidateFixGitBranchMoves(t *testing.T) {
	testValidateFixGit(t, revisionScenario{moveBranch: true})
}

func TestValidateFixGitBranchMovesWithRescanMiss(t *testing.T) {
	testValidateFixGit(t, revisionScenario{moveBranch: true, missRescan: true})
}

func TestValidateFixGitSameCommit(t *testing.T) {
	testValidateFixGit(t, revisionScenario{})
}

func TestValidateFixGitUngraded(t *testing.T) {
	testValidateFixGit(t, revisionScenario{ungradedVerify: true})
}

func TestValidateFixGitResumedAtNewCommit(t *testing.T) {
	testValidateFixGit(t, revisionScenario{moveBranch: true, resumeVerify: true})
}

func TestValidateFixGitResumedWithRejectedGrade(t *testing.T) {
	testValidateFixGit(t, revisionScenario{resumeVerify: true, ungradedVerify: true})
}

func TestValidateFixGitResumedSameCommit(t *testing.T) {
	testValidateFixGit(t, revisionScenario{resumeVerify: true})
}

type revisionScenario struct {
	moveBranch     bool
	missRescan     bool
	ungradedVerify bool
	resumeVerify   bool
}

func testValidateFixGit(t *testing.T, scenario revisionScenario) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	source := newRevisionRepository(t, ctx, scenario.moveBranch)

	s, closeDB := newTestServer(t)
	defer closeDB()
	resumeGate := configureRevisionWorker(t, ctx, s, scenario, source)
	w := s.Worker
	s.Queue.Reconfigure(1)
	w.Register(s.Queue)
	if scenario.resumeVerify {
		// Resume explicitly through the server; keep account-reset timers out
		// of this controlled interleaving. Registered queue handlers stay live.
		w.Queue = nil
	}
	stopped := make(chan struct{})
	go func() { s.Queue.Start(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }()
	repo := db.Repository{URL: source.url, Name: "revision-demo"}
	audit := db.Skill{Name: "revision-demo-audit", Body: "Run the local boundary check.", OutputKind: "findings", OutputFile: "report.json", Version: 1, Active: true}
	verify := db.Skill{Name: verifySkillName, Body: "Run the local boundary check three times.", OutputKind: "verify", OutputFile: "report.json", Version: 1, Active: true}
	for _, row := range []any{&repo, &audit, &verify} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	baselineID, err := s.enqueueSkillWith(ctx, repo.ID, audit.ID, ScanOpts{Ref: "baseline"})
	if err != nil {
		t.Fatal(err)
	}
	baseline := waitRevisionScan(t, ctx, s, baselineID)
	if baseline.Commit != source.baselineCommit {
		t.Fatalf("baseline checkout = %s, want %s", baseline.Commit, source.baselineCommit)
	}
	var finding db.Finding
	if err := s.DB.Where("scan_id = ?", baselineID).First(&finding).Error; err != nil {
		t.Fatal(err)
	}
	var initialVerifyID uint
	if scenario.resumeVerify {
		initialVerifyID = resumeRevisionVerification(t, ctx, s, repo.ID, verify.ID, finding.ID)
	}
	app := httptest.NewServer(s.Handler())
	defer app.Close()
	anchorID := postRevisionValidation(t, ctx, app.URL, repo.ID, finding.ID)
	if scenario.resumeVerify {
		close(resumeGate)
	}
	anchor := waitRevisionScan(t, ctx, s, anchorID)
	if got := mustRevisionGit(t, ctx, source.work, "ls-remote", repo.URL, "refs/heads/candidate"); !strings.HasPrefix(got, source.commitB+"\t") {
		t.Fatalf("HTTPS remote did not advertise B: %s", got)
	}
	verifyScan, grade := checkRevisionVerification(t, s, source, scenario, anchor, finding.ID, initialVerifyID)
	var report struct {
		FixCommit string `json:"fix_commit"`
		Counts    struct {
			Resolved  int `json:"resolved"`
			Surviving int `json:"surviving"`
			New       int `json:"new"`
		} `json:"counts"`
		Resolved []fixValidationFinding `json:"resolved"`
		Verify   []fixValidationVerify  `json:"verify"`
	}
	if err := json.Unmarshal([]byte(anchor.Report), &report); err != nil {
		t.Fatal(err)
	}
	t.Logf("E2E_REPORT %s", anchor.Report)
	if out := os.Getenv("SCRUTINEER_REVISION_E2E_ARTIFACT_DIR"); out != "" {
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Fatal(err)
		}
		evidence := map[string]any{"verify_run_number": verifyScan.RunNumber, "grade_run_number": grade.RunNumber, "grade_commit": grade.Commit, "resumed_verify": scenario.resumeVerify, "branch_moved": scenario.moveBranch, "ungraded_verify": scenario.ungradedVerify, "verification_score": grade.Score, "simulated_rescan_miss": scenario.missRescan, "baseline_commit": source.baselineCommit, "commit_a": source.commitA, "commit_b": source.commitB, "verify_scan_id": verifyScan.ID, "anchor_scan_id": anchor.ID, "verification_report": json.RawMessage(verifyScan.Report), "combined_report": json.RawMessage(anchor.Report), "baseline_log": baseline.Log, "verify_log": verifyScan.Log, "anchor_log": anchor.Log}
		raw, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "evidence.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		mustRevisionGit(t, ctx, source.work, "bundle", "create", filepath.Join(out, "repository.bundle"), "--all")
	}
	wantResolved, wantSurviving := 0, 1
	if scenario.missRescan || !scenario.moveBranch {
		wantResolved, wantSurviving = 1, 0
	}
	if report.FixCommit != source.commitB || report.Counts.Resolved != wantResolved ||
		report.Counts.Surviving != wantSurviving || report.Counts.New != 0 || len(report.Verify) != 1 {
		t.Fatalf("unexpected report: %s", anchor.Report)
	}
	if wantResolved == 1 && (len(report.Resolved) != 1 || report.Resolved[0].FindingID != finding.ID) {
		t.Fatalf("missed finding missing from resolved: %s", anchor.Report)
	}
	wantStatus := "fixed"
	if scenario.moveBranch || scenario.ungradedVerify || scenario.resumeVerify {
		wantStatus = "unverified"
	}
	if report.Verify[0].Status != wantStatus {
		t.Fatalf("combined status = %q, want %q; verify_commit=%s anchor_commit=%s verification_score=%v", report.Verify[0].Status, wantStatus, verifyScan.Commit, source.commitB, grade.Score)
	}
}

func waitRevisionScan(t *testing.T, ctx context.Context, s *Server, id uint) db.Scan {
	t.Helper()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		var scan db.Scan
		if err := s.DB.First(&scan, id).Error; err != nil {
			t.Fatal(err)
		}
		if scan.Status.Terminal() {
			if scan.Status != db.ScanDone {
				t.Fatalf("scan %d %s: %s\n%s", id, scan.Status, scan.Error, scan.Log)
			}
			if scan.BaselineScanID == nil || strings.Contains(scan.Report, `"fix_scan_id"`) {
				return scan
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for scan %d: %v\n%s", id, ctx.Err(), scan.Log)
		case <-tick.C:
		}
	}
}

func revisionVerificationReport(reproduced bool, evidence string) (verification.Report, error) {
	report := revisionFixedReport(evidence)
	if reproduced {
		report.Status = "confirmed"
		report.AttackTree.Verdict = "reachable"
		report.AttackTree.Blockers = []string{}
		root := report.AttackTree.RootID
		report.AttackTree.Nodes[0].Status = "satisfied"
		report.AttackTree.Nodes = append(report.AttackTree.Nodes,
			verification.AttackTreeNode{ID: "entry", ParentID: &root, Kind: "entry_point", Description: "Supply the CLI index", Status: "satisfied", Evidence: report.Evidence},
			verification.AttackTreeNode{ID: "sink", ParentID: &root, Kind: "sink", Description: "Bounds check accepts index eight", Status: "satisfied", Evidence: report.Evidence})
		report.Criteria.ReproducesThreeOfThree.Verdict = "pass"
		report.Criteria.ClaimedFailureClass.Verdict = "pass"
		report.Criteria.PublicInterfaceToFirstPartySink.Verdict = "pass"
		for i := range report.Attempts {
			report.Attempts[i].Outcome = "reproduced"
			report.Attempts[i].FailureClass = "off-by-one"
			report.Attempts[i].CrashSite = "main.go:3"
		}
		if err := report.Validate(); err != nil {
			return report, err
		}
	}
	return report, nil
}

type revisionRepository struct {
	work, bare, url                  string
	baselineCommit, commitA, commitB string
}

func newRevisionRepository(t *testing.T, ctx context.Context, moveBranch bool) revisionRepository {
	t.Helper()
	for _, tool := range []string{"git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required: %v", tool, err)
		}
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", "0")
	t.Setenv("GIT_AUTHOR_DATE", "2026-11-09T12:00:00Z")
	t.Setenv("GIT_COMMITTER_DATE", "2026-11-09T12:00:00Z")
	work, remoteRoot := t.TempDir(), t.TempDir()
	git := func(dir string, args ...string) string {
		t.Helper()
		out, err := revisionGit(ctx, dir, args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	commit := func(operator, message string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, "main.go"), []byte(strings.ReplaceAll(revisionTarget, "BOUND", operator)), 0o644); err != nil {
			t.Fatal(err)
		}
		git(work, "add", "main.go")
		git(work, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message)
		return git(work, "rev-parse", "HEAD")
	}
	git(work, "init", "--quiet", "-b", "candidate")
	baselineCommit := commit("<=", "baseline: off-by-one")
	git(work, "tag", "baseline")
	commitA := commit("<", "A: fix the boundary")
	bare := filepath.Join(remoteRoot, "origin.git")
	git(work, "clone", "--quiet", "--bare", work, bare)
	git(work, "remote", "add", "origin", bare)
	git(work, "--git-dir", bare, "update-server-info")
	commitB := commitA
	if moveBranch {
		commitB = commit("<=", "B: reintroduce the boundary bug")
	}
	if got := git(work, "--git-dir", bare, "rev-parse", "refs/heads/candidate"); got != commitA {
		t.Fatalf("remote moved before verification: %s", got)
	}
	gitServer := httptest.NewTLSServer(http.FileServer(http.Dir(remoteRoot)))
	t.Cleanup(gitServer.Close)
	ca := filepath.Join(t.TempDir(), "git-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gitServer.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSL_CAINFO", ca)

	return revisionRepository{work: work, bare: bare, url: gitServer.URL + "/origin.git", baselineCommit: baselineCommit, commitA: commitA, commitB: commitB}
}

func configureRevisionWorker(t *testing.T, ctx context.Context, s *Server, scenario revisionScenario, source revisionRepository) chan struct{} {
	t.Helper()
	w := s.Worker
	w.Log, w.DataDir, w.FullClone = s.Log, t.TempDir(), true
	var pausedOnce atomic.Bool
	resumeGate := make(chan struct{})
	w.OnEvent = func(scanID, _ uint, name, data string) {
		if name == "scan-status" && data == string(db.ScanRunning) && pausedOnce.Load() {
			checkRevisionResumeMetadata(t, s, scanID, source.commitB)
		}
		if scenario.resumeVerify && name == "scan-log" {
			if pausedOnce.Load() && strings.Contains(data, "REAL_CHECKOUT skill=verify commit=") {
				select {
				case <-resumeGate:
				case <-ctx.Done():
				}
			}
			if strings.Contains(data, " -> fixed") && pausedOnce.CompareAndSwap(false, true) {
				found, err := w.CancelWithAudit(scanID, worker.OveragePauseReason, nil)
				if err != nil || !found {
					t.Errorf("pause after grading: found=%t err=%v", found, err)
				}
				t.Logf("PAUSE_AFTER_ACCEPTED_GRADE scan=%d", scanID)
			}
		}
		if name == "scan-log" {
			t.Logf("TRACE scan=%d %s", scanID, strings.TrimSpace(data))
		}
	}
	w.Runner = revisionProbeRunner{verifyRuns: new(atomic.Uint32), resumeVerify: scenario.resumeVerify, missRescan: scenario.missRescan, ungradedVerify: scenario.ungradedVerify, advance: func(ctx context.Context) error {
		if _, err := revisionGit(ctx, source.work, "push", "--quiet", "origin", "candidate"); err != nil {
			return err
		}
		if _, err := revisionGit(ctx, source.work, "--git-dir", source.bare, "update-server-info"); err != nil {
			return err
		}
		t.Logf("REAL_PUSH candidate: A=%s -> B=%s", source.commitA, source.commitB)
		return nil
	}}
	return resumeGate
}

func resumeRevisionVerification(t *testing.T, ctx context.Context, s *Server, repoID, verifyID, findingID uint) uint {
	t.Helper()
	initialVerifyID, err := s.enqueueSkillWith(ctx, repoID, verifyID, ScanOpts{Ref: "candidate", FindingID: &findingID})
	if err != nil {
		t.Fatal(err)
	}
	var paused db.Scan
	for {
		if err := s.DB.First(&paused, initialVerifyID).Error; err != nil {
			t.Fatal(err)
		}
		if paused.Status == db.ScanPaused {
			break
		}
		if paused.Status.Terminal() {
			t.Fatalf("verification did not pause: %s", paused.Status)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	var firstGrade db.FindingVerification
	if err := s.DB.Where("scan_id = ?", initialVerifyID).First(&firstGrade).Error; err != nil || firstGrade.Score == nil || firstGrade.Status != "fixed" {
		t.Fatalf("missing initial accepted grade: %+v: %v", firstGrade, err)
	}
	t.Logf("INITIAL_GRADE scan=%d commit=%s status=%s", initialVerifyID, paused.Commit, firstGrade.Status)
	if err := s.resumeScan(ctx, &paused); err != nil {
		t.Fatal(err)
	}
	return initialVerifyID
}

func postRevisionValidation(t *testing.T, ctx context.Context, baseURL string, repoID, findingID uint) uint {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"ref": {"candidate"}, "finding_ids": {fmt.Sprint(findingID)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/repositories/%d/validate-fix", baseURL, repoID), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	asOperator(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusSeeOther {
		t.Fatalf("validate-fix HTTP %d: %s: %v", response.StatusCode, body, err)
	}
	var anchorID uint
	if _, err := fmt.Sscanf(response.Header.Get("Location"), "/scans/%d", &anchorID); err != nil {
		t.Fatal(err)
	}
	return anchorID
}

func checkRevisionVerification(t *testing.T, s *Server, source revisionRepository, scenario revisionScenario, anchor db.Scan, findingID, initialVerifyID uint) (db.Scan, db.FindingVerification) {
	t.Helper()
	var verifyScan db.Scan
	if err := s.DB.Where("finding_id = ? AND skill_name = ?", findingID, verifySkillName).First(&verifyScan).Error; err != nil {
		t.Fatal(err)
	}
	wantVerifyCommit := source.commitA
	if scenario.resumeVerify {
		wantVerifyCommit = source.commitB
	}
	if verifyScan.Status != db.ScanDone || verifyScan.Commit != wantVerifyCommit || anchor.Commit != source.commitB {
		t.Fatalf("wrong execution revisions: verify=%s/%s anchor=%s/%s", verifyScan.Status, verifyScan.Commit, anchor.Status, anchor.Commit)
	}
	if scenario.resumeVerify {
		var raw struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal([]byte(verifyScan.Report), &raw); err != nil {
			t.Fatal(err)
		}
		wantRaw := "fixed"
		if scenario.moveBranch {
			wantRaw = "confirmed"
		}
		if verifyScan.ID != initialVerifyID || raw.Status != wantRaw {
			t.Fatalf("wrong resumed report: scan=%d report=%s", verifyScan.ID, verifyScan.Report)
		}
		t.Logf("RESUMED_CURRENT_REPORT scan=%d commit=%s status=%s", verifyScan.ID, verifyScan.Commit, raw.Status)
	}
	var grade db.FindingVerification
	if err := s.DB.Where("scan_id = ?", verifyScan.ID).First(&grade).Error; err != nil || grade.Status != "fixed" || (grade.Score == nil) != (scenario.ungradedVerify && !scenario.resumeVerify) {
		t.Fatalf("unexpected verification grading: %+v: %v", grade, err)
	}
	wantRun := uint(1)
	if scenario.resumeVerify {
		wantRun = 2
	}
	if verifyScan.RunNumber != wantRun || grade.RunNumber != 1 || grade.Commit != source.commitA {
		t.Fatalf("wrong grading execution identity: scan run=%d grade run=%d grade commit=%s", verifyScan.RunNumber, grade.RunNumber, grade.Commit)
	}
	t.Logf("GRADE_IDENTITY scan=%d run=%d grade_run=%d grade_commit=%s", verifyScan.ID, verifyScan.RunNumber, grade.RunNumber, grade.Commit)
	return verifyScan, grade
}

func mustRevisionGit(t *testing.T, ctx context.Context, dir string, args ...string) string {
	t.Helper()
	out, err := revisionGit(ctx, dir, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func checkRevisionResumeMetadata(t *testing.T, s *Server, scanID uint, anchorCommit string) {
	t.Helper()
	var scan db.Scan
	if err := s.DB.First(&scan, scanID).Error; err != nil {
		t.Errorf("read resumed claim: %v", err)
		return
	}
	if scan.FindingID == nil {
		return
	}
	entries := s.fixValidationVerdicts([]db.Finding{{ID: *scan.FindingID}}, scan.Ref, anchorCommit)
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Errorf("marshal pending verdict: %v", err)
		return
	}
	t.Logf("RESUME_CLAIM_REPORT scan=%d stored_commit=%q %s", scan.ID, scan.Commit, raw)
	if len(entries) != 1 {
		t.Errorf("pending verdicts = %s", raw)
		return
	}
	if scan.RunNumber != 2 || entries[0].RunNumber != 2 || entries[0].Status != "pending" {
		t.Errorf("wrong pending execution identity: %s", raw)
	}
	if scan.Commit != "" || entries[0].Commit != "" {
		t.Errorf("prior commit exposed for new execution before checkout: stored=%q verdict=%s", scan.Commit, raw)
	}
}
