package pool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadStatePreservesRegisteredPhysicalIdentity(t *testing.T) {
	for _, kind := range []string{"symlink", "case"} {
		t.Run(kind, func(t *testing.T) {
			dir, target, entry := inspectionFixture(t)
			if kind == "symlink" {
				alias := filepath.Join(t.TempDir(), "logical-pool")
				if err := os.Symlink(dir, alias); err != nil {
					t.Skip(err)
				}
				relative, err := filepath.Rel(dir, target)
				if err != nil {
					t.Fatal(err)
				}
				entry.Path = filepath.Join(alias, relative)
			} else {
				alias := strings.ToUpper(target)
				a, _ := os.Stat(target)
				b, err := os.Stat(alias)
				if err != nil || !os.SameFile(a, b) || alias == target {
					t.Skip("case-sensitive filesystem")
				}
				entry.Path = alias
			}
			if err := WriteState(dir, State{Worktrees: []WorktreeEntry{entry}}); err != nil {
				t.Fatal(err)
			}
			before := snapshotPoolFiles(t, dir)
			for range 2 {
				state, err := ReadState(dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(state.Worktrees) != 1 || state.Worktrees[0].Path != entry.Path || state.Worktrees[0].LeaseID != entry.LeaseID || state.Worktrees[0].LeaseHolder != entry.LeaseHolder {
					t.Fatalf("discovery manufactured an alias row or changed retained ownership: rows=%d", len(state.Worktrees))
				}
				inspected, err := InspectLease(dir, target)
				if err != nil || inspected.LeaseID != entry.LeaseID {
					t.Fatalf("single retained alias rejected: %v", err)
				}
			}
			assertPoolUnchanged(t, dir, before)
			statuses, err := List(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(statuses) != 1 || statuses[0].LeaseID != entry.LeaseID || statuses[0].LeaseHolder != entry.LeaseHolder {
				t.Fatal("lifecycle listing manufactured an alias shadow")
			}
		})
	}
}

func TestReadStateDoesNotReconcileExistingPhysicalDuplicates(t *testing.T) {
	dir, target, entry := inspectionFixture(t)
	alias := filepath.Join(t.TempDir(), "logical-pool")
	if err := os.Symlink(dir, alias); err != nil {
		t.Skip(err)
	}
	relative, err := filepath.Rel(dir, target)
	if err != nil {
		t.Fatal(err)
	}
	original := entry
	original.Path = filepath.Join(alias, relative)
	shadow := entry
	shadow.Leased = false
	shadow.LeaseID = ""
	shadow.LeaseHolder = ""
	shadow.LeasedAt = time.Time{}
	// Keep an ordinary unleased entry. The reader must not erase either stored
	// registration or choose an owner to make a strict inspector pass.
	if err := WriteState(dir, State{Worktrees: []WorktreeEntry{original, shadow}}); err != nil {
		t.Fatal(err)
	}
	before := snapshotPoolFiles(t, dir)
	state, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Worktrees) != 2 {
		t.Fatal("reader silently reconciled existing registrations")
	}
	if _, err := InspectLease(dir, target); err == nil {
		t.Fatal("existing ambiguity was admitted")
	}
	assertPoolUnchanged(t, dir, before)
}

func TestReadStateStillQuarantinesDifferentUnregisteredDirectory(t *testing.T) {
	dir, _, entry := inspectionFixture(t)
	other := makeFakeWorktree(t, dir, "2", "unregistered")
	state, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Worktrees) != 2 || state.Worktrees[0].LeaseID != entry.LeaseID || state.Worktrees[1].Path != other || state.Worktrees[1].LeaseHolder != RecoveredLeaseHolder || !state.Worktrees[1].Leased {
		t.Fatal("a distinct unknown directory lost conservative recovery")
	}
}
