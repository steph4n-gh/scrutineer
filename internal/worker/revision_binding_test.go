package worker

import (
	"testing"

	"scrutineer/internal/db"
)

func TestStartScan_resumeClearsPreviousCommit(t *testing.T) {
	w, scan, _ := newRecipeWorker(t, "", "")
	if err := w.startScan(&scan); err != nil {
		t.Fatal(err)
	}
	scan.Commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	scan.Status = db.ScanPaused
	if err := w.DB.Save(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("status", db.ScanQueued).Error; err != nil {
		t.Fatal(err)
	}
	var resumed db.Scan
	if err := w.DB.First(&resumed, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := w.startScan(&resumed); err != nil {
		t.Fatal(err)
	}
	var stored db.Scan
	if err := w.DB.First(&stored, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	t.Logf("RESUME_CLAIM run=%d memory_commit=%q stored_commit=%q", resumed.RunNumber, resumed.Commit, stored.Commit)
	if resumed.RunNumber != 2 || stored.RunNumber != 2 {
		t.Fatalf("resume did not advance execution identity: memory=%d stored=%d", resumed.RunNumber, stored.RunNumber)
	}
	if resumed.Commit != "" || stored.Commit != "" {
		t.Errorf("stale prior commit after resume: memory=%q stored=%q; want unknown until checkout", resumed.Commit, stored.Commit)
	}
}
