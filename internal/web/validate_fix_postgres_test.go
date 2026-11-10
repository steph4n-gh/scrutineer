package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/testutil"
	"scrutineer/internal/worker"
)

// Only the analysis and source preparation are fixtures. The PostgreSQL
// migration, queue, worker claim, parser, grade write and aggregation are real.
type postgresMigrationVerifyRunner struct{}

func (postgresMigrationVerifyRunner) SkillDir(root, name string) string {
	return filepath.Join(root, "skills", name)
}

func (postgresMigrationVerifyRunner) RunSkill(context.Context, worker.SkillJob, func(worker.Event)) (worker.SkillResult, error) {
	report, err := json.Marshal(revisionFixedReport("Authored PostgreSQL migration fixture; no production analysis was executed."))
	return worker.SkillResult{Report: string(report)}, err
}

type postgresLegacyVerificationState struct {
	Scans    []db.Scan
	Findings []db.Finding
	Grades   []db.FindingVerification
	Note     db.FindingNote
}

func TestPostgresFixValidationLegacyUpgrade(t *testing.T) {
	dsn := testutil.PostgresDSN(t)
	gdb := openPostgresUpgradeDB(t, dsn)
	repo, before := seedPostgresLegacyVerification(t, gdb)
	closePostgresUpgradeDB(t, gdb)
	migratePostgresLegacyConcurrently(t, dsn)
	// Repeated production startup must preserve the populated legacy database.
	for pass := 1; pass <= 2; pass++ {
		gdb = openPostgresUpgradeDB(t, dsn)
		checkPostgresLegacyUpgrade(t, gdb, before, pass)
		if pass == 1 {
			closePostgresUpgradeDB(t, gdb)
		}
	}
	defer closePostgresUpgradeDB(t, gdb)
	checkFreshPostgresVerification(t, gdb, repo.ID, before)
}

func openPostgresUpgradeDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	gdb, err := db.OpenBackend(db.Options{Dialect: db.DialectPostgres, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	return gdb
}

func closePostgresUpgradeDB(t *testing.T, gdb *gorm.DB) {
	t.Helper()
	conn, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func seedPostgresLegacyVerification(t *testing.T, gdb *gorm.DB) (db.Repository, postgresLegacyVerificationState) {
	t.Helper()
	// Recreate the immediately preceding schema before inserting legacy data.
	// The new columns really are absent while the old rows are written.
	for _, ddl := range []string{
		`ALTER TABLE scans DROP COLUMN run_number`,
		`ALTER TABLE finding_verifications DROP COLUMN "commit"`,
		`ALTER TABLE finding_verifications DROP COLUMN run_number`,
	} {
		if err := gdb.Exec(ddl).Error; err != nil {
			t.Fatal(err)
		}
	}
	const commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	repo := db.Repository{URL: "https://example.invalid/pg-upgrade", Name: "legacy-upgrade"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	baseline := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: "legacy-audit", Commit: "original-A"}
	if err := gdb.Omit("RunNumber").Create(&baseline).Error; err != nil {
		t.Fatal(err)
	}
	zero, nonzero := 0.0, 0.75
	state := postgresLegacyVerificationState{Scans: []db.Scan{baseline}}
	for i, score := range []*float64{&zero, &nonzero, nil} {
		finding := db.Finding{RepositoryID: repo.ID, ScanID: baseline.ID, Title: "legacy finding",
			Fingerprint: []string{"legacy-zero", "legacy-scored", "legacy-rejected"}[i], Commit: "original-A", Status: db.FindingNew}
		if err := gdb.Create(&finding).Error; err != nil {
			t.Fatal(err)
		}
		scan := db.Scan{RepositoryID: repo.ID, FindingID: &finding.ID, SkillName: verifySkillName,
			Status: db.ScanDone, Ref: "candidate", Commit: commit, Report: "{\"status\":\"fixed\",\"evidence\":\"legacy\\nΩ\"}"}
		if err := gdb.Omit("RunNumber").Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		grade := db.FindingVerification{FindingID: finding.ID, ScanID: scan.ID, Status: "fixed", Score: score, Report: scan.Report}
		if err := gdb.Omit("Commit", "RunNumber").Create(&grade).Error; err != nil {
			t.Fatal(err)
		}
		state.Findings = append(state.Findings, finding)
		state.Scans = append(state.Scans, scan)
		state.Grades = append(state.Grades, grade)
	}
	historical := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, Ref: "candidate", Commit: commit,
		BaselineScanID: &baseline.ID, Report: `{"counts":{"resolved":3},"verify":[{"status":"fixed"}],"historical":true}`}
	if err := gdb.Omit("RunNumber").Create(&historical).Error; err != nil {
		t.Fatal(err)
	}
	state.Scans = append(state.Scans, historical)
	note := db.FindingNote{FindingID: state.Findings[0].ID, Body: "Legacy evidence remains readable.\nΩ", By: "fixture"}
	if err := gdb.Create(&note).Error; err != nil {
		t.Fatal(err)
	}
	state.Note = note
	return repo, readPostgresLegacyState(t, gdb, state)
}

func readPostgresLegacyState(t *testing.T, gdb *gorm.DB, before postgresLegacyVerificationState) postgresLegacyVerificationState {
	t.Helper()
	var scanIDs, findingIDs, gradeIDs []uint
	for _, row := range before.Scans {
		scanIDs = append(scanIDs, row.ID)
	}
	for _, row := range before.Findings {
		findingIDs = append(findingIDs, row.ID)
	}
	for _, row := range before.Grades {
		gradeIDs = append(gradeIDs, row.ID)
	}
	var state postgresLegacyVerificationState
	for _, query := range []struct {
		ids  []uint
		rows any
	}{
		{scanIDs, &state.Scans}, {findingIDs, &state.Findings}, {gradeIDs, &state.Grades},
	} {
		if err := gdb.Where("id IN ?", query.ids).Order("id").Find(query.rows).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := gdb.First(&state.Note, before.Note.ID).Error; err != nil {
		t.Fatal(err)
	}
	return state
}

func migratePostgresLegacyConcurrently(t *testing.T, dsn string) {
	t.Helper()
	// Multiple upgraded processes may start against the populated old schema.
	// Production's advisory lock must serialize the pending DDL without loss.
	const starters = 4
	results := make(chan error, starters)
	start := make(chan struct{})
	var ready sync.WaitGroup
	for range starters {
		ready.Add(1)
		go func() {
			ready.Done()
			<-start
			opened, err := db.OpenBackend(db.Options{Dialect: db.DialectPostgres, DSN: dsn})
			if err == nil {
				conn, dbErr := opened.DB()
				err = dbErr
				if dbErr == nil {
					err = conn.Close()
				}
			}
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	for range starters {
		if err := <-results; err != nil {
			t.Errorf("concurrent legacy upgrade: %v", err)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	t.Logf("CONCURRENT_UPGRADE: %d startup migrations completed on the populated legacy database", starters)
}

func checkPostgresLegacyUpgrade(t *testing.T, gdb *gorm.DB, before postgresLegacyVerificationState, pass int) {
	t.Helper()
	var gradeIDs []uint
	for _, row := range before.Grades {
		gradeIDs = append(gradeIDs, row.ID)
	}
	if got := readPostgresLegacyState(t, gdb, before); !reflect.DeepEqual(got, before) {
		t.Fatalf("migration %d changed legacy evidence:\nbefore=%+v\nafter=%+v", pass, before, got)
	}
	for _, column := range []struct{ table, column string }{
		{"scans", "run_number"}, {"finding_verifications", "run_number"},
	} {
		var nullable string
		if err := gdb.Raw(`SELECT is_nullable FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ? AND column_name = ?`, column.table, column.column).Scan(&nullable).Error; err != nil || nullable != "NO" {
			t.Fatalf("%s.%s nullable=%q: %v", column.table, column.column, nullable, err)
		}
	}
	var unknown int64
	if err := gdb.Model(&db.FindingVerification{}).Where("id IN ? AND run_number = 0 AND \"commit\" IS NULL", gradeIDs).Count(&unknown).Error; err != nil || unknown != 3 {
		t.Fatalf("migration guessed legacy grade identity: unknown=%d err=%v", unknown, err)
	}
	if !gdb.Migrator().HasIndex(&db.FindingVerification{}, "idx_finding_verification_scan") {
		t.Fatal("migration lost the grading uniqueness index")
	}
	t.Logf("UPGRADE_PASS %d: three grades preserved (zero, nonzero, NULL scores); commit remains NULL, run numbers remain zero", pass)
}

func checkFreshPostgresVerification(t *testing.T, gdb *gorm.DB, repoID uint, before postgresLegacyVerificationState) {
	t.Helper()
	const commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	conn, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	q, err := queue.New(conn, log, 1, queue.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	w := &worker.Worker{DB: gdb, Log: log, DataDir: t.TempDir(), Runner: postgresMigrationVerifyRunner{},
		PrepareRepoSrc: func(_ context.Context, _, _, root string, _ func(worker.Event)) (string, error) {
			return commit, os.MkdirAll(filepath.Join(root, "src"), 0o755)
		}}
	s, err := New(gdb, q, log, NewBroker(), w)
	if err != nil {
		t.Fatal(err)
	}
	s.DisableEcosystems()
	verdicts := s.fixValidationVerdicts(before.Findings, "candidate", commit)
	if len(verdicts) != 3 {
		t.Fatalf("legacy verdicts=%+v, want three", verdicts)
	}
	for _, v := range verdicts {
		if v.Status != "unverified" || v.RunNumber != 0 {
			t.Fatalf("legacy evidence became trusted: %+v", v)
		}
	}
	t.Log("LEGACY_VERDICTS: all three unverified, including the accepted zero-score legacy row")
	skill := db.Skill{Name: verifySkillName, Active: true, Version: 1, Body: "Authored migration test fixture.", OutputKind: "verify", OutputFile: "report.json"}
	if err := gdb.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	w.Register(q)
	stopped := make(chan struct{})
	go func() { q.Start(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }()
	id, err := s.enqueueSkillWith(ctx, repoID, skill.ID, ScanOpts{Ref: "candidate", FindingID: &before.Findings[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	fresh := waitRevisionScan(t, ctx, s, id)
	var grade db.FindingVerification
	if err := gdb.Where("scan_id = ?", fresh.ID).First(&grade).Error; err != nil {
		t.Fatal(err)
	}
	if fresh.RunNumber != 1 || grade.RunNumber != 1 || grade.Commit != commit || grade.Score == nil {
		t.Fatalf("fresh grade did not acquire execution identity: scan=%+v grade=%+v", fresh, grade)
	}
	verdicts = s.fixValidationVerdicts(before.Findings, "candidate", commit)
	if len(verdicts) != 3 {
		t.Fatalf("post-upgrade verdicts=%+v, want three", verdicts)
	}
	for _, v := range verdicts {
		want := "unverified"
		if v.FindingID == before.Findings[0].ID {
			want = "fixed"
		}
		if v.Status != want {
			t.Fatalf("post-upgrade verdict=%+v, want %s", v, want)
		}
	}
	// Fresh analysis can update the canonical finding's calibration and
	// activity time. Earlier scan/grade records and notes remain immutable.
	got := readPostgresLegacyState(t, gdb, before)
	if !reflect.DeepEqual(got.Scans, before.Scans) || !reflect.DeepEqual(got.Grades, before.Grades) || !reflect.DeepEqual(got.Note, before.Note) {
		t.Fatal("fresh verification rewrote legacy evidence or historical reports")
	}
	t.Logf("FRESH_VERIFICATION: scan=%d run=%d grade_run=%d commit=%s status=fixed; legacy scan/grade evidence unchanged", fresh.ID, fresh.RunNumber, grade.RunNumber, grade.Commit)
}
