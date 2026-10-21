//go:build !windows

package pool

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func aliasFixture(t *testing.T) (AliasRequest, []byte) {
	t.Helper()
	dir, target, k := inspectionFixture(t)
	dir, e := filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	target, e = filepath.EvalSymlinks(target)
	if e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(t.TempDir(), "logical-pool")
	if e = os.Symlink(dir, alias); e != nil {
		t.Fatal(e)
	}
	relative, e := filepath.Rel(dir, target)
	if e != nil {
		t.Fatal(e)
	}
	shadow := k
	shadow.Path = target
	shadow.Leased = false
	shadow.LeaseID = ""
	shadow.LeaseHolder = ""
	shadow.LeasedAt = time.Time{}
	k.Path = filepath.Join(alias, relative)
	sibling := shadow
	sibling.Name = "2"
	sibling.Path = makeFakeWorktree(t, dir, "2", "sibling")
	if e = WriteState(dir, State{Worktrees: []WorktreeEntry{sibling, k, shadow}}); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(stateFilePath(dir))
	if e != nil {
		t.Fatal(e)
	}
	var s State
	if e = StrictAliasJSON(data, &s); e != nil {
		t.Fatal(e)
	}
	k, shadow = s.Worktrees[1], s.Worktrees[2]
	return AliasRequest{Pool: dir, Target: target, Name: k.Name, LeaseID: k.LeaseID, Holder: k.LeaseHolder, LeasedAt: k.LeasedAt, StateHash: aliasHash(data), KeeperHash: aliasHash(aliasJSON(k)), ShadowHash: aliasHash(aliasJSON(shadow))}, data
}
func aliasPreviewFixture(t *testing.T) (AliasRequest, AliasPreview, []byte) {
	t.Helper()
	r, b := aliasFixture(t)
	p, e := PreviewAlias(r)
	if e != nil {
		t.Fatal(e)
	}
	return r, p, b
}
func aliasRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestAliasPreviewApplyPreservesOwnerAndSiblings(t *testing.T) {
	r, before := aliasFixture(t)
	snapshot := snapshotPoolFiles(t, r.Pool)
	p, e := PreviewAlias(r)
	if e != nil {
		t.Fatal(e)
	}
	p2, e := PreviewAlias(r)
	if e != nil {
		t.Fatal(e)
	}
	if p.Token == p2.Token || p.Nonce == p2.Nonce || p.Before != r.StateHash || p.After == p.Before {
		t.Fatal("preview not fresh or not exact")
	}
	assertPoolUnchanged(t, r.Pool, snapshot)
	if _, e = InspectLease(r.Pool, r.Target); e == nil {
		t.Fatal("ambiguous original unexpectedly admitted")
	}
	result, e := ApplyAlias(r, p, syntheticAliasFence)
	if e != nil || result.Outcome != "confirmed" {
		t.Fatalf("apply: %s %v", result.Outcome, e)
	}
	var old, now State
	StrictAliasJSON(before, &old)
	StrictAliasJSON(aliasRead(t, stateFilePath(r.Pool)), &now)
	if len(now.Worktrees) != 2 || !bytes.Equal(aliasJSON(old.Worktrees[0]), aliasJSON(now.Worktrees[0])) {
		t.Fatal("sibling or row order changed")
	}
	keeper := old.Worktrees[1]
	keeper.Path = r.Target
	key := aliasRead(t, stateKeyPath(r.Pool))
	defer clear(key)
	keeper.SeedInventoryDigest = seedInventoryDigest(key, keeper)
	if !bytes.Equal(aliasJSON(keeper), aliasJSON(now.Worktrees[1])) {
		t.Fatal("keeper changed beyond path/inventory digest")
	}
	inspected, e := InspectLease(r.Pool, r.Target)
	if e != nil || inspected.LeaseID != r.LeaseID || inspected.LeaseHolder != r.Holder || !inspected.LeasedAt.Equal(r.LeasedAt) {
		t.Fatalf("preserved lease rejected: %v", e)
	}
	for _, file := range []string{"treehouse-state.key", "treehouse-state.lock"} {
		if snapshot[file] != snapshotPoolFiles(t, r.Pool)[file] {
			t.Fatal("key or lock changed")
		}
	}
	for _, name := range []string{"before.json", "candidate.json", "manifest.json"} {
		fi, e := os.Stat(filepath.Join(result.Transaction, name))
		if e != nil || fi.Mode().Perm() != 0600 {
			t.Fatal("backup permissions")
		}
	}
	recovered, e := RecoverAlias(r, result.Transaction, false, nil)
	if e != nil || recovered.Outcome != "applied-receipt-unconfirmed" {
		t.Fatalf("read-only receipt recovery: %v", e)
	}
	rolled, e := RecoverAlias(r, result.Transaction, true, syntheticAliasFence)
	if e != nil || rolled.Outcome != "rolled-back" || !bytes.Equal(before, aliasRead(t, stateFilePath(r.Pool))) {
		t.Fatalf("rollback: %v", e)
	}
	if _, e = InspectLease(r.Pool, r.Target); e == nil {
		t.Fatal("rollback relaxed inspector")
	}
	if _, e = ApplyAlias(r, p, syntheticAliasFence); e == nil {
		t.Fatal("consumed preview replay after rollback admitted")
	}
	t.Log("confirmed: fresh preview read-only; exact keeper/siblings preserved; strict lease passes only candidate; exact rollback and consumed-token denial")
}

func TestAliasApplyRejectsChangedPreviewOrAuthority(t *testing.T) {
	for _, kind := range []string{"empty-token", "forged-token", "expired", "future-expiry", "request", "state", "sibling", "key-inode", "lock-inode", "target-inode", "marker-changed", "busy", "backup-collision"} {
		t.Run(kind, func(t *testing.T) {
			r, p, before := aliasPreviewFixture(t)
			keyBefore := aliasRead(t, stateKeyPath(r.Pool))
			var held *os.File
			switch kind {
			case "empty-token":
				p.Token = ""
			case "forged-token":
				p.After = strings.Repeat("a", 64)
			case "expired", "future-expiry":
				if kind == "expired" {
					p.Expires = time.Now().Add(-time.Second)
				} else {
					p.Expires = time.Now().Add(time.Hour)
				}
				p.Token = ""
				p.Token = aliasMAC(keyBefore, "treehouse.alias-preview.v1", p)
			case "request":
				r.Holder = "another-owner"
			case "state":
				os.WriteFile(stateFilePath(r.Pool), append(before, '\n'), 0600)
			case "sibling":
				var state State
				StrictAliasJSON(before, &state)
				state.Worktrees[0].BaseBranch = "changed"
				WriteState(r.Pool, state)
			case "key-inode", "lock-inode":
				path := stateKeyPath(r.Pool)
				data := keyBefore
				if kind == "lock-inode" {
					path = lockFilePath(r.Pool)
					data = aliasRead(t, path)
				}
				os.Rename(path, path+".retained")
				os.WriteFile(path, data, 0600)
			case "target-inode":
				os.Rename(r.Target, r.Target+"-retained")
				os.Mkdir(r.Target, 0755)
			case "marker-changed":
				path := filepath.Join(r.Target, ".git")
				b := aliasRead(t, path)
				os.WriteFile(path, append(b, '\n'), 0600)
			case "busy":
				var e error
				held, e = openInspectionFile(lockFilePath(r.Pool))
				if e != nil {
					t.Fatal(e)
				}
				if e = tryLockFile(held); e != nil {
					t.Fatal(e)
				}
				defer held.Close()
				defer unlockFile(held)
			case "backup-collision":
				os.Mkdir(aliasTransactionPath(r, p), 0700)
			}
			stateBefore := aliasRead(t, stateFilePath(r.Pool))
			_, e := ApplyAlias(r, p, syntheticAliasFence)
			if e == nil {
				t.Fatal("changed preview/authority admitted")
			}
			if !bytes.Equal(stateBefore, aliasRead(t, stateFilePath(r.Pool))) {
				t.Fatal("denied apply mutated state")
			}
		})
	}
}

func TestAliasPreviewRejectsUnsafeRowsWithoutHealing(t *testing.T) {
	for _, kind := range []string{"foreign-holder", "foreign-id", "foreign-time", "shadow-leased", "shadow-owner", "keeper-owner", "destroying", "recovered", "unknown-inventory", "nonempty-inventory", "invalid-hmac", "third-physical", "third-name", "missing-key", "missing-lock", "legacy", "unknown-json", "duplicate-json"} {
		t.Run(kind, func(t *testing.T) {
			r, before := aliasFixture(t)
			var state State
			StrictAliasJSON(before, &state)
			k, w := &state.Worktrees[1], &state.Worktrees[2]
			switch kind {
			case "foreign-holder":
				k.LeaseHolder = "different"
			case "foreign-id":
				k.LeaseID = strings.Repeat("f", 32)
			case "foreign-time":
				k.LeasedAt = k.LeasedAt.Add(time.Second)
			case "shadow-leased":
				w.Leased = true
			case "shadow-owner":
				w.OwnerPID = 123
			case "keeper-owner":
				k.OwnerPID = 123
			case "destroying":
				w.Destroying = true
			case "recovered":
				w.RecoveryReason = "untrusted"
			case "unknown-inventory":
				k.SeedInventoryKnown = false
			case "nonempty-inventory":
				k.SeededPaths = []string{".env.synthetic"}
			case "third-physical":
				other := *w
				other.Name = "3"
				state.Worktrees = append(state.Worktrees, other)
			case "third-name":
				state.Worktrees[0].Name = r.Name
			}
			if e := WriteState(r.Pool, state); e != nil {
				t.Fatal(e)
			}
			data := aliasRead(t, stateFilePath(r.Pool))
			StrictAliasJSON(data, &state)
			if kind == "invalid-hmac" {
				state.Worktrees[1].SeedInventoryDigest = "bad"
				data = aliasJSON(state)
			}
			if kind == "legacy" {
				state.Version = 0
				data = aliasJSON(state)
			}
			if kind == "unknown-json" {
				data = append([]byte(`{"unmodelled":true,`), data[1:]...)
			}
			if kind == "duplicate-json" {
				data = append([]byte(`{"version":4,`), data[1:]...)
			}
			if e := os.WriteFile(stateFilePath(r.Pool), data, 0600); e != nil {
				t.Fatal(e)
			}
			// Refresh exact hashes to ensure semantic predicates, not only stale state,
			// reject each invalid shape.
			r.StateHash = aliasHash(data)
			r.KeeperHash = aliasHash(aliasJSON(state.Worktrees[1]))
			r.ShadowHash = aliasHash(aliasJSON(state.Worktrees[2]))
			if kind == "missing-key" {
				os.Remove(stateKeyPath(r.Pool))
			}
			if kind == "missing-lock" {
				os.Remove(lockFilePath(r.Pool))
			}
			snapshot := snapshotPoolFiles(t, r.Pool)
			if _, e := PreviewAlias(r); e == nil {
				t.Fatal("unsafe rows admitted")
			}
			assertPoolUnchanged(t, r.Pool, snapshot)
		})
	}
}

func TestAliasTransactionRollbackAndLostReceipt(t *testing.T) {
	for _, stage := range []string{"before-write", "verify", "lost-receipt"} {
		t.Run(stage, func(t *testing.T) {
			r, p, before := aliasPreviewFixture(t)
			result, e := applyAlias(r, p, func(at string) error {
				if at == stage {
					return fmt.Errorf("synthetic interruption")
				}
				return nil
			}, syntheticAliasFence)
			if e == nil {
				t.Fatal("fault was not exercised")
			}
			expected := map[string]string{"before-write": "not-applied", "verify": "rolled-back", "lost-receipt": "accepted-but-unconfirmed"}[stage]
			if stage == "lost-receipt" && result.VerifiedStateHash != "" {
				t.Fatal("uncertain outcome claimed persisted state verification")
			}
			if result.Outcome != expected {
				t.Fatalf("wrong outcome: %s", result.Outcome)
			}
			observed, e := RecoverAlias(r, result.Transaction, false, nil)
			if e != nil {
				t.Fatal(e)
			}
			if stage == "lost-receipt" {
				if observed.Outcome != "applied-receipt-unconfirmed" {
					t.Fatal("lost receipt blindly treated as rejection")
				}
				if _, e = RecoverAlias(r, result.Transaction, true, syntheticAliasFence); e != nil {
					t.Fatal(e)
				}
			} else if observed.Outcome != "not-applied-or-rolled-back" {
				t.Fatal("pre-write/rollback misclassified")
			}
			if !bytes.Equal(before, aliasRead(t, stateFilePath(r.Pool))) {
				t.Fatal("exact original backup not restored")
			}
			t.Logf("stage=%s outcome=%s authenticatedRecovery=%s", stage, result.Outcome, observed.Outcome)
		})
	}
}

func TestAliasRollbackRejectsStaleOrTamperedBackup(t *testing.T) {
	for _, kind := range []string{"state-drift", "backup-tamper", "manifest-tamper", "key-replaced", "lock-replaced", "backup-symlink", "public-backup"} {
		t.Run(kind, func(t *testing.T) {
			r, p, _ := aliasPreviewFixture(t)
			result, e := ApplyAlias(r, p, syntheticAliasFence)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "state-drift":
				data := aliasRead(t, stateFilePath(r.Pool))
				os.WriteFile(stateFilePath(r.Pool), append(data, '\n'), 0600)
			case "backup-tamper":
				os.WriteFile(filepath.Join(result.Transaction, "before.json"), []byte("tampered"), 0600)
			case "manifest-tamper":
				os.WriteFile(filepath.Join(result.Transaction, "manifest.json"), []byte(`{}`), 0600)
			case "key-replaced", "lock-replaced":
				path := stateKeyPath(r.Pool)
				if kind == "lock-replaced" {
					path = lockFilePath(r.Pool)
				}
				b := aliasRead(t, path)
				os.Rename(path, path+".retained")
				os.WriteFile(path, b, 0600)
			case "backup-symlink":
				path := filepath.Join(result.Transaction, "before.json")
				os.Rename(path, path+".retained")
				os.Symlink(path+".retained", path)
			case "public-backup":
				os.Chmod(filepath.Join(result.Transaction, "before.json"), 0644)
			}
			before := aliasRead(t, stateFilePath(r.Pool))
			if _, e = RecoverAlias(r, result.Transaction, true, syntheticAliasFence); e == nil {
				t.Fatal("unsafe rollback admitted")
			}
			if !bytes.Equal(before, aliasRead(t, stateFilePath(r.Pool))) {
				t.Fatal("unsafe rollback overwrote newer state")
			}
		})
	}
}

func TestAliasStrictJSON(t *testing.T) {
	for _, s := range []string{`{"pool":"a","pool":"b"}`, `{"extra":1}`, `{} {}`, `{"pool":{"x":1,"x":2}}`} {
		var r AliasRequest
		if e := StrictAliasJSON([]byte(s), &r); e == nil {
			t.Fatal("unsafe JSON accepted")
		}
	}
}

func TestAliasCommitBoundaryAndAutomaticRollbackFailClosed(t *testing.T) {
	for _, stage := range []string{"before-write", "verify"} {
		t.Run(stage, func(t *testing.T) {
			r, p, _ := aliasPreviewFixture(t)
			var external []byte
			result, e := applyAlias(r, p, func(at string) error {
				if at != stage {
					return nil
				}
				external = append(aliasRead(t, stateFilePath(r.Pool)), '\n')
				if err := os.WriteFile(stateFilePath(r.Pool), external, 0600); err != nil {
					t.Fatal(err)
				}
				if stage == "verify" {
					return fmt.Errorf("synthetic verification failure after concurrent state change")
				}
				return nil
			}, syntheticAliasFence)
			if e == nil || !bytes.Equal(external, aliasRead(t, stateFilePath(r.Pool))) {
				t.Fatal("stale transaction overwrote changed state")
			}
			if stage == "verify" && result.Outcome != "inconclusive" {
				t.Fatal("failed rollback concealed uncertainty")
			}
		})
	}
}

// This seam is available only in disposable tests. It makes no live exclusion
// claim and is never selectable through production CLI or environment state.
func syntheticAliasFence(AliasRequest) (func() error, func(), error) {
	return func() error { return nil }, func() {}, nil
}

func TestAliasMutationRequiresHeldWriterFence(t *testing.T) {
	r, p, _ := aliasPreviewFixture(t)
	before := snapshotPoolFiles(t, r.Pool)
	if _, e := ApplyAlias(r, p, nil); e == nil {
		t.Fatal("pool lock mistaken for legacy writer exclusion")
	}
	if _, e := ApplyAlias(r, p, func(AliasRequest) (func() error, func(), error) { return nil, nil, nil }); e == nil {
		t.Fatal("unheld writer fence admitted")
	}
	assertPoolUnchanged(t, r.Pool, before)
	held := false
	fence := func(AliasRequest) (func() error, func(), error) {
		held = true
		return func() error {
			if !held {
				return fmt.Errorf("synthetic fence lost")
			}
			return nil
		}, func() { held = false }, nil
	}
	result, e := applyAlias(r, p, func(stage string) error {
		if !held {
			t.Fatal("writer fence released before commit/verification")
		}
		if stage == "verify" {
			lock, e := openInspectionFile(lockFilePath(r.Pool))
			if e != nil {
				t.Fatal(e)
			}
			defer lock.Close()
			if e = tryLockFile(lock); e == nil {
				unlockFile(lock)
				t.Fatal("transaction released pool lock during strict verification")
			}
		}
		return nil
	}, fence)
	if e != nil || held {
		t.Fatalf("held verification fence: %v", e)
	}
	if _, e = RecoverAlias(r, result.Transaction, true, nil); e == nil {
		t.Fatal("explicit rollback bypassed writer fence")
	}
}

func TestAliasCanonicalKeeperStillNeedsPreventionForLogicalDiscovery(t *testing.T) {
	r, p, _ := aliasPreviewFixture(t)
	result, e := ApplyAlias(r, p, syntheticAliasFence)
	if e != nil {
		t.Fatal(e)
	}
	var m aliasManifest
	if e = StrictAliasJSON(aliasRead(t, filepath.Join(result.Transaction, "manifest.json")), &m); e != nil {
		t.Fatal(e)
	}
	var old State
	StrictAliasJSON(aliasRead(t, filepath.Join(result.Transaction, "before.json")), &old)
	logicalPool := filepath.Dir(filepath.Dir(old.Worktrees[1].Path))
	// Reproduce the legacy algorithm's lexical discovery predicate without
	// invoking a legacy binary or mutating the actual fixture state.
	canonicalKeeper := r.Target
	logicalDiscovered := filepath.Join(logicalPool, r.Name, filepath.Base(r.Target))
	if filepath.Clean(canonicalKeeper) == filepath.Clean(logicalDiscovered) {
		t.Fatal("fixture lacks distinct logical spelling")
	}
	a, e := os.Stat(canonicalKeeper)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.Stat(logicalDiscovered)
	if e != nil || !os.SameFile(a, b) {
		t.Fatal("fixture no longer aliases one object")
	}
	// Prevention recognizes the same object even when discovery starts at the
	// logical root. The canonical spelling alone would fail the lexical check.
	read, e := ReadState(logicalPool)
	if e != nil || len(read.Worktrees) != 2 {
		t.Fatalf("prevention from logical root: %v", e)
	}
	t.Log("legacy lexical predicate would discover a shadow from logical root; prevention preserves exactly one selected physical registration")
}

func TestAliasLostWriterFenceStopsCommit(t *testing.T) {
	r, p, before := aliasPreviewFixture(t)
	held := true
	fence := func(AliasRequest) (func() error, func(), error) {
		return func() error {
			if !held {
				return fmt.Errorf("synthetic lost fence")
			}
			return nil
		}, func() { held = false }, nil
	}
	result, e := applyAlias(r, p, func(stage string) error {
		if stage == "before-write" {
			held = false
		}
		return nil
	}, fence)
	if e == nil || result.Outcome != "not-applied" || !bytes.Equal(before, aliasRead(t, stateFilePath(r.Pool))) {
		t.Fatal("lost fence allowed commit")
	}
}

func TestAliasJSONCanonicalTagsRejectCaseAndUnicodeAliases(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		out        any
	}{
		{"request-same-value", `{"pool":"a","POOL":"a"}`, &AliasRequest{}},
		{"request-conflict", `{"pool":"a","POOL":"b"}`, &AliasRequest{}},
		{"request-alias-only", `{"PoOl":"a"}`, &AliasRequest{}},
		{"unicode-long-s", `{"ſtate_sha256":"a"}`, &AliasRequest{}},
		{"unicode-kelvin-k", `{"Keeper_sha256":"a"}`, &AliasRequest{}},
		{"state-nested-same", `{"version":4,"worktrees":[{"lease_id":"a","LEASE_ID":"a"}]}`, &State{}},
		{"state-nested-conflict", `{"version":4,"worktrees":[{"lease_holder":"a","LeAsE_HoLdEr":"b"}]}`, &State{}},
		{"state-root-case", `{"Version":4,"worktrees":[]}`, &State{}},
		{"preview-same", `{"token":"a","TOKEN":"a"}`, &AliasPreview{}},
		{"preview-conflict", `{"before_sha256":"a","BEFORE_SHA256":"b"}`, &AliasPreview{}},
		{"manifest-request", `{"request":{"pool":"a","POOL":"a"}}`, &aliasManifest{}},
		{"manifest-preview", `{"preview":{"nonce":"a","NONCE":"b"}}`, &aliasManifest{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := StrictAliasJSON([]byte(tc.data), tc.out); e == nil {
				t.Fatal("noncanonical ownership field accepted")
			}
		})
	}
	r, _, _ := aliasPreviewFixture(t)
	for _, v := range []any{r, State{Version: 4}, AliasPreview{}, aliasManifest{Request: r}} {
		out := reflect.New(reflect.TypeOf(v)).Interface()
		if e := StrictAliasJSON(aliasJSON(v), out); e != nil {
			t.Fatalf("canonical generated schema rejected: %v", e)
		}
	}
}
