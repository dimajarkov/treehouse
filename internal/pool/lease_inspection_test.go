package pool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kunchenguid/treehouse/v3/internal/process"
)

func inspectionFixture(t *testing.T) (string, string, WorktreeEntry) {
	t.Helper()
	repo, dir := setupLocalRepo(t)
	lease, err := AcquireLeaseInfo(repo, dir, 1, nil, "synthetic-holder")
	if err != nil {
		t.Fatal(err)
	}
	state, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, lease.Path, state.Worktrees[0]
}
func snapshotPoolFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	result := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = fmt.Sprintf("%s:%d:%s", info.ModTime(), info.Mode(), b)
	}
	return result
}
func assertPoolUnchanged(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	after := snapshotPoolFiles(t, dir)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Fatal("read-only lease inspection changed pool files")
	}
}
func TestInspectLeaseFreshReadOnlyAndStatusParity(t *testing.T) {
	dir, path, entry := inspectionFixture(t)
	before := snapshotPoolFiles(t, dir)
	old := findProcessesInWorktree
	findProcessesInWorktree = func(string) ([]process.ProcessInfo, error) {
		t.Fatal("inspection enumerated processes")
		return nil, nil
	}
	defer func() { findProcessesInWorktree = old }()
	for range 2 {
		got, err := InspectLease(dir, path)
		if err != nil {
			t.Fatal(err)
		}
		if got.SchemaVersion != "treehouse.lease-inspection.v1" || got.Path != path || got.LeaseID != entry.LeaseID || got.LeaseHolder != entry.LeaseHolder || got.Status != StatusLeased {
			t.Fatalf("incorrect lease identity: %+v", got)
		}
		assertPoolUnchanged(t, dir, before)
	}
	findProcessesInWorktree = old
	statuses, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].LeaseID != entry.LeaseID || statuses[0].LeaseHolder != entry.LeaseHolder || statuses[0].Status != StatusLeased {
		t.Fatal("inspection disagrees with existing leased status")
	}
	entry.LeaseID = strings.Repeat("a", 32)
	entry.LeaseHolder = "new-holder"
	if err := WriteState(dir, State{Worktrees: []WorktreeEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	got, err := InspectLease(dir, path)
	if err != nil || got.LeaseID != entry.LeaseID || got.LeaseHolder != entry.LeaseHolder {
		t.Fatal("inspection cached positive authority")
	}
	entry.Leased = false
	if err := WriteState(dir, State{Worktrees: []WorktreeEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectLease(dir, path); err == nil {
		t.Fatal("returned lease remained authorized")
	}
}
func TestInspectLeaseDeniesUncertainStateWithoutRepair(t *testing.T) {
	for _, kind := range []string{"missing-state", "corrupt-state", "future-version", "missing-key", "bad-digest", "unleased", "destroying", "recovered", "recovery-error", "missing-id", "missing-holder", "duplicate-path", "duplicate-alias", "markerless", "missing-lock", "busy-lock", "legacy-state", "state-symlink", "key-symlink", "lock-symlink", "dangling-marker", "duplicate-case"} {
		t.Run(kind, func(t *testing.T) {
			dir, path, entry := inspectionFixture(t)
			entries := []WorktreeEntry{entry}
			switch kind {
			case "unleased":
				entries[0].Leased = false
			case "destroying":
				entries[0].Destroying = true
			case "recovered":
				entries[0].LeaseHolder = RecoveredLeaseHolder
			case "recovery-error":
				entries[0].RecoveryError = "unreadable marker"
			case "missing-id":
				entries[0].LeaseID = ""
			case "missing-holder":
				entries[0].LeaseHolder = ""
			case "duplicate-path":
				entries = append(entries, entry)
			case "duplicate-case":
				alias := strings.ToUpper(path)
				first, _ := os.Stat(path)
				second, err := os.Stat(alias)
				if err != nil || !os.SameFile(first, second) || alias == path {
					t.Skip("case-sensitive filesystem")
				}
				duplicate := entry
				duplicate.Name = "other"
				duplicate.Path = alias
				entries = append(entries, duplicate)
			case "duplicate-alias":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(path, alias); err != nil {
					t.Skip(err)
				}
				duplicate := entry
				duplicate.Name = "other"
				duplicate.Path = alias
				entries = append(entries, duplicate)
			}
			if err := WriteState(dir, State{Worktrees: entries}); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing-state":
				os.Remove(stateFilePath(dir))
			case "corrupt-state":
				os.WriteFile(stateFilePath(dir), []byte("{"), 0600)
			case "future-version":
				os.WriteFile(stateFilePath(dir), []byte(`{"version":999,"worktrees":[]}`), 0600)
			case "legacy-state":
				data, _ := os.ReadFile(stateFilePath(dir))
				var state State
				json.Unmarshal(data, &state)
				state.Version = 0
				data, _ = json.Marshal(state)
				os.WriteFile(stateFilePath(dir), data, 0600)
			case "state-symlink", "key-symlink", "lock-symlink":
				source := stateFilePath(dir)
				if kind == "key-symlink" {
					source = stateKeyPath(dir)
				}
				if kind == "lock-symlink" {
					source = lockFilePath(dir)
				}
				target := filepath.Join(t.TempDir(), "original")
				data, _ := os.ReadFile(source)
				os.WriteFile(target, data, 0600)
				os.Remove(source)
				if err := os.Symlink(target, source); err != nil {
					t.Skip(err)
				}
			case "dangling-marker":
				os.WriteFile(filepath.Join(path, ".git"), []byte("gitdir: /missing-synthetic-administrative-directory\n"), 0600)
			case "missing-key":
				os.Remove(stateKeyPath(dir))
			case "bad-digest":
				data, _ := os.ReadFile(stateFilePath(dir))
				var s State
				json.Unmarshal(data, &s)
				s.Worktrees[0].SeedInventoryDigest = "invalid"
				data, _ = json.Marshal(s)
				os.WriteFile(stateFilePath(dir), data, 0600)
			case "markerless":
				os.Remove(filepath.Join(path, ".git"))
			case "missing-lock":
				os.Remove(lockFilePath(dir))
			}
			var unlock func()
			if kind == "busy-lock" {
				f, err := os.OpenFile(lockFilePath(dir), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err = lockFile(f); err != nil {
					t.Fatal(err)
				}
				unlock = func() { unlockFile(f); f.Close() }
				defer unlock()
			}
			before := snapshotPoolFiles(t, dir)
			start := time.Now()
			if _, err := InspectLease(dir, path); err == nil {
				t.Fatal("uncertain lease was admitted")
			}
			if kind == "busy-lock" && time.Since(start) > time.Second {
				t.Fatal("busy lock was not refused immediately")
			}
			assertPoolUnchanged(t, dir, before)
		})
	}
}

func TestInspectLeaseCanonicalAliasAndMissingPool(t *testing.T) {
	dir, path, entry := inspectionFixture(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Skip(err)
	}
	got, err := InspectLease(dir, alias)
	if err != nil || got.Path != path || got.LeaseID != entry.LeaseID {
		t.Fatalf("canonical alias failed: %+v %v", got, err)
	}
	missing := filepath.Join(t.TempDir(), "missing-pool")
	if _, err := InspectLease(missing, path); err == nil {
		t.Fatal("missing pool admitted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("inspection created a pool")
	}
}

// This is a synthetic pool receipt, not a live Arena admission/OTP budget.
func TestInspectLeaseSyntheticTiming(t *testing.T) {
	dir, path, entry := inspectionFixture(t)
	state, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 20; i++ {
		sibling := entry
		sibling.Name = fmt.Sprint(i)
		sibling.Path = makeFakeWorktree(t, dir, sibling.Name, "synthetic-sibling")
		state.Worktrees = append(state.Worktrees, sibling)
	}
	if err := WriteState(dir, state); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 5 {
		if _, err := InspectLease(dir, path); err != nil {
			t.Fatal(err)
		}
	}
	inspect := time.Since(start)
	start = time.Now()
	if _, err := List(dir); err != nil {
		t.Fatal(err)
	}
	listing := time.Since(start)
	t.Logf("synthetic timing: registered=20 inspection_mean_us=%d ordinary_list_us=%d; no live pool used", inspect.Microseconds()/5, listing.Microseconds())
}
