//go:build !windows

package pool

import (
	"bytes"
	"os"
	"testing"
)

func quarantinedAliasFixture(t *testing.T, position int) (AliasRequest, []byte, WorktreeEntry) {
	t.Helper()
	r, before := aliasFixture(t)
	var state State
	if e := StrictAliasJSON(before, &state); e != nil {
		t.Fatal(e)
	}
	sibling := state.Worktrees[0]
	sibling.SeedInventoryKnown = false
	sibling.SeedInventoryDigest = ""
	sibling.Leased = true
	sibling.LeaseID = ""
	sibling.LeaseHolder = RecoveredLeaseHolder
	sibling.RecoveryReason = "unknown seed inventory retained"
	state.Worktrees = append([]WorktreeEntry{}, state.Worktrees[1:]...)
	state.Worktrees = append(state.Worktrees, WorktreeEntry{})
	copy(state.Worktrees[position+1:], state.Worktrees[position:])
	state.Worktrees[position] = sibling
	before = aliasJSON(state)
	if e := os.WriteFile(stateFilePath(r.Pool), before, 0600); e != nil {
		t.Fatal(e)
	}
	r.StateHash = aliasHash(before)
	return r, before, sibling
}

func TestAliasRepairPreservesUnrelatedQuarantine(t *testing.T) {
	for _, position := range []int{0, 1, 2} {
		t.Run(string(rune('0'+position)), func(t *testing.T) {
			r, before, sibling := quarantinedAliasFixture(t, position)
			snapshot := snapshotPoolFiles(t, r.Pool)
			p, e := PreviewAlias(r)
			if e != nil {
				t.Fatalf("unrelated quarantine blocked selected repair: %v", e)
			}
			assertPoolUnchanged(t, r.Pool, snapshot)
			result, e := ApplyAlias(r, p, syntheticAliasFence)
			if e != nil || result.Outcome != "confirmed" {
				t.Fatalf("apply: %s %v", result.Outcome, e)
			}
			var candidate State
			if e = StrictAliasJSON(aliasRead(t, stateFilePath(r.Pool)), &candidate); e != nil {
				t.Fatal(e)
			}
			expectedPosition := position
			if position == 2 {
				expectedPosition = 1
			}
			if len(candidate.Worktrees) != 2 || !bytes.Equal(aliasJSON(candidate.Worktrees[expectedPosition]), aliasJSON(sibling)) {
				t.Fatal("quarantined sibling fields/order changed")
			}
			lease, e := InspectLease(r.Pool, r.Target)
			if e != nil || lease.LeaseID != r.LeaseID {
				t.Fatalf("selected lease rejected: %v", e)
			}
			if _, e = InspectLease(r.Pool, sibling.Path); e == nil {
				t.Fatal("quarantine was promoted to valid ownership")
			}
			rollback, e := RecoverAlias(r, result.Transaction, true, syntheticAliasFence)
			if e != nil || rollback.Outcome != "rolled-back" || !bytes.Equal(before, aliasRead(t, stateFilePath(r.Pool))) {
				t.Fatalf("rollback: %s %v", rollback.Outcome, e)
			}
		})
	}
}

func TestAliasRepairRejectsChangedQuarantinedSibling(t *testing.T) {
	r, _, _ := quarantinedAliasFixture(t, 0)
	p, e := PreviewAlias(r)
	if e != nil {
		t.Fatal(e)
	}
	var state State
	if e = StrictAliasJSON(aliasRead(t, stateFilePath(r.Pool)), &state); e != nil {
		t.Fatal(e)
	}
	state.Worktrees[0].RecoveryReason = "newer quarantine observation"
	newer := aliasJSON(state)
	if e = os.WriteFile(stateFilePath(r.Pool), newer, 0600); e != nil {
		t.Fatal(e)
	}
	result, e := ApplyAlias(r, p, syntheticAliasFence)
	if e == nil || result.Outcome != "" || !bytes.Equal(newer, aliasRead(t, stateFilePath(r.Pool))) {
		t.Fatal("stale sibling state was overwritten")
	}
}

func TestAliasRepairRejectsMissingQuarantinedSibling(t *testing.T) {
	r, _, sibling := quarantinedAliasFixture(t, 0)
	if e := os.Rename(sibling.Path, sibling.Path+".retained"); e != nil {
		t.Fatal(e)
	}
	snapshot := snapshotPoolFiles(t, r.Pool)
	if _, e := PreviewAlias(r); e == nil {
		t.Fatal("missing sibling identity was accepted")
	}
	assertPoolUnchanged(t, r.Pool, snapshot)
}

func TestAliasRepairRejectsUnauthenticatedKnownSibling(t *testing.T) {
	r, before := aliasFixture(t)
	var state State
	if e := StrictAliasJSON(before, &state); e != nil {
		t.Fatal(e)
	}
	state.Worktrees[0].SeedInventoryDigest = "bad"
	changed := aliasJSON(state)
	if e := os.WriteFile(stateFilePath(r.Pool), changed, 0600); e != nil {
		t.Fatal(e)
	}
	r.StateHash = aliasHash(changed)
	snapshot := snapshotPoolFiles(t, r.Pool)
	if _, e := PreviewAlias(r); e == nil {
		t.Fatal("bad known sibling inventory was accepted")
	}
	assertPoolUnchanged(t, r.Pool, snapshot)
}

func TestAliasRepairRejectsQuarantinedThirdClaim(t *testing.T) {
	for _, kind := range []string{"physical", "name"} {
		t.Run(kind, func(t *testing.T) {
			r, before, _ := quarantinedAliasFixture(t, 0)
			var state State
			if e := StrictAliasJSON(before, &state); e != nil {
				t.Fatal(e)
			}
			if kind == "physical" {
				state.Worktrees[0].Path = r.Target
			} else {
				state.Worktrees[0].Name = r.Name
			}
			changed := aliasJSON(state)
			if e := os.WriteFile(stateFilePath(r.Pool), changed, 0600); e != nil {
				t.Fatal(e)
			}
			r.StateHash = aliasHash(changed)
			snapshot := snapshotPoolFiles(t, r.Pool)
			if _, e := PreviewAlias(r); e == nil {
				t.Fatal("quarantined third ownership claim accepted")
			}
			assertPoolUnchanged(t, r.Pool, snapshot)
		})
	}
}
