//go:build !windows

package pool

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func recoveredShadowFixture(t *testing.T) (AliasRequest, []byte) {
	t.Helper()
	r, before := aliasFixture(t)
	var state State
	if err := StrictAliasJSON(before, &state); err != nil {
		t.Fatal(err)
	}
	w := &state.Worktrees[2]
	w.Leased = true
	w.LeaseHolder = RecoveredLeaseHolder
	w.LeasedAt = state.Worktrees[1].LeasedAt.Add(time.Minute)
	w.CreatedAt = w.LeasedAt
	w.SeedInventoryKnown = false
	w.SeedInventoryDigest = ""
	w.RecoveryReason = "tracked changes are present; preserve them"
	before = aliasJSON(state)
	if err := os.WriteFile(stateFilePath(r.Pool), before, 0600); err != nil {
		t.Fatal(err)
	}
	r.StateHash = aliasHash(before)
	r.ShadowHash = aliasHash(aliasJSON(*w))
	r.RecoveredShadow = true
	return r, before
}

func TestRecoveredAliasPreservesWorkAndOriginalLease(t *testing.T) {
	r, before := recoveredShadowFixture(t)
	file := filepath.Join(r.Target, "unfinished.txt")
	work := []byte("unfinished work must survive repair and rollback\n")
	if err := os.WriteFile(file, work, 0600); err != nil {
		t.Fatal(err)
	}
	marker := aliasRead(t, filepath.Join(r.Target, ".git"))
	snapshot := snapshotPoolFiles(t, r.Pool)
	p, err := PreviewAlias(r)
	if err != nil {
		t.Fatal(err)
	}
	assertPoolUnchanged(t, r.Pool, snapshot)
	denied := r
	denied.RecoveredShadow = false
	if _, err = ApplyAlias(denied, p, syntheticAliasFence); err == nil {
		t.Fatal("request mode changed after preview was accepted")
	}
	result, err := ApplyAlias(r, p, syntheticAliasFence)
	if err != nil || result.Outcome != "confirmed" {
		t.Fatalf("apply %v %v", result, err)
	}
	var old, now State
	StrictAliasJSON(before, &old)
	StrictAliasJSON(aliasRead(t, stateFilePath(r.Pool)), &now)
	expected := old.Worktrees[1]
	expected.Path = r.Target
	key := aliasRead(t, stateKeyPath(r.Pool))
	defer clear(key)
	expected.SeedInventoryDigest = seedInventoryDigest(key, expected)
	if len(now.Worktrees) != 2 || !bytes.Equal(aliasJSON(now.Worktrees[0]), aliasJSON(old.Worktrees[0])) || !bytes.Equal(aliasJSON(now.Worktrees[1]), aliasJSON(expected)) {
		t.Fatal("original lease or sibling changed")
	}
	lease, err := InspectLease(r.Pool, r.Target)
	if err != nil || lease.LeaseID != r.LeaseID || lease.LeaseHolder != r.Holder || !lease.LeasedAt.Equal(r.LeasedAt) {
		t.Fatalf("original lease not preserved: %v", err)
	}
	if !bytes.Equal(work, aliasRead(t, file)) || !bytes.Equal(marker, aliasRead(t, filepath.Join(r.Target, ".git"))) {
		t.Fatal("worktree changed")
	}
	rolled, err := RecoverAlias(r, result.Transaction, true, syntheticAliasFence)
	if err != nil || rolled.Outcome != "rolled-back" || !bytes.Equal(before, aliasRead(t, stateFilePath(r.Pool))) || !bytes.Equal(work, aliasRead(t, file)) {
		t.Fatalf("rollback failed %v", err)
	}
}

func TestRecoveredAliasRequiresExplicitNarrowAuthority(t *testing.T) {
	for _, kind := range []string{"no-opt-in", "durable-shadow", "foreign-holder", "owner", "seeded-path", "known-inventory", "digest", "no-reason", "recovery-error", "destroying", "old-recovery", "created-mismatch", "keeper-auth"} {
		t.Run(kind, func(t *testing.T) {
			r, before := recoveredShadowFixture(t)
			var state State
			StrictAliasJSON(before, &state)
			w := &state.Worktrees[2]
			switch kind {
			case "no-opt-in":
				r.RecoveredShadow = false
			case "durable-shadow":
				w.LeaseID = "11111111111111111111111111111111"
			case "foreign-holder":
				w.LeaseHolder = "another-owner"
			case "owner":
				w.OwnerPID = 123
			case "seeded-path":
				w.SeededPaths = []string{"unknown"}
			case "known-inventory":
				w.SeedInventoryKnown = true
			case "digest":
				w.SeedInventoryDigest = "bad"
			case "no-reason":
				w.RecoveryReason = ""
			case "recovery-error":
				w.RecoveryError = "unresolved"
			case "destroying":
				w.Destroying = true
			case "old-recovery":
				w.LeasedAt = state.Worktrees[1].LeasedAt.Add(-time.Minute)
				w.CreatedAt = w.LeasedAt
			case "created-mismatch":
				w.CreatedAt = w.CreatedAt.Add(time.Second)
			case "keeper-auth":
				state.Worktrees[1].SeedInventoryDigest = "bad"
			}
			changed := aliasJSON(state)
			os.WriteFile(stateFilePath(r.Pool), changed, 0600)
			r.StateHash = aliasHash(changed)
			r.KeeperHash = aliasHash(aliasJSON(state.Worktrees[1]))
			r.ShadowHash = aliasHash(aliasJSON(*w))
			snapshot := snapshotPoolFiles(t, r.Pool)
			if _, err := PreviewAlias(r); err == nil {
				t.Fatal("unsafe recovered shadow accepted")
			}
			assertPoolUnchanged(t, r.Pool, snapshot)
		})
	}
}
