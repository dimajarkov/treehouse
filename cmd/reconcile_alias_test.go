//go:build !windows

package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kunchenguid/treehouse/v3/internal/pool"
)

func cmdAliasHash(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func TestReconcileAliasCLIRequiresExplicitPreviewAndModes(t *testing.T) {
	repo, home := setupTestRepo(t)
	stdout, stderr, code := runTreehouse(t, repo, home, nil, "get", "--lease", "--lease-holder", "synthetic-reconcile-owner", "--json")
	if code != 0 {
		t.Fatalf("lease fixture: %s", stderr)
	}
	var lease leaseJSONResult
	if e := json.Unmarshal([]byte(stdout), &lease); e != nil {
		t.Fatal(e)
	}
	target, e := filepath.EvalSymlinks(lease.Path)
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Dir(filepath.Dir(target))
	state, e := pool.ReadState(dir)
	if e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(t.TempDir(), "logical-pool")
	if e = os.Symlink(dir, alias); e != nil {
		t.Fatal(e)
	}
	rel, e := filepath.Rel(dir, target)
	if e != nil {
		t.Fatal(e)
	}
	keeper := state.Worktrees[0]
	shadow := keeper
	keeper.Path = filepath.Join(alias, rel)
	shadow.Path = target
	shadow.Leased = false
	shadow.LeaseID = ""
	shadow.LeaseHolder = ""
	shadow.LeasedAt = time.Time{}
	if e = pool.WriteState(dir, pool.State{Worktrees: []pool.WorktreeEntry{keeper, shadow}}); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(dir, "treehouse-state.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = pool.StrictAliasJSON(data, &state); e != nil {
		t.Fatal(e)
	}
	kb, _ := json.Marshal(state.Worktrees[0])
	sb, _ := json.Marshal(state.Worktrees[1])
	req := pool.AliasRequest{Pool: dir, Target: target, Name: keeper.Name, LeaseID: keeper.LeaseID, Holder: keeper.LeaseHolder, LeasedAt: keeper.LeasedAt, StateHash: cmdAliasHash(data), KeeperHash: cmdAliasHash(kb), ShadowHash: cmdAliasHash(sb)}
	inputs := t.TempDir()
	request := filepath.Join(inputs, "request.json")
	preview := filepath.Join(inputs, "preview.json")
	rb, _ := json.Marshal(req)
	os.WriteFile(request, rb, 0600)
	before, _ := json.Marshal(poolFileSnapshot(t, dir))
	for _, args := range [][]string{
		{"reconcile-alias"},
		{"reconcile-alias", "preview"},
		{"reconcile-alias", "apply", "--request", request},
		{"reconcile-alias", "preview", "--request", request, "--preview", preview},
		{"reconcile-alias", "preview", "--request", request, "--root", filepath.Join(home, "foreign")},
		{"reconcile-alias", "inspect", "--request", request},
		{"reconcile-alias", "rollback", "--request", request},
		{"reconcile-alias", "preview", "--request", request, "extra"},
	} {
		out, _, status := runTreehouse(t, repo, home, nil, args...)
		if status == 0 || strings.TrimSpace(out) != "" {
			t.Fatalf("invalid command returned receipt: %v", args)
		}
	}
	after, _ := json.Marshal(poolFileSnapshot(t, dir))
	if string(before) != string(after) {
		t.Fatal("invalid mode changed pool")
	}
	out, errout, status := runTreehouse(t, repo, home, nil, "reconcile-alias", "preview", "--request", request)
	if status != 0 {
		t.Fatalf("preview: %s", errout)
	}
	var p pool.AliasPreview
	if e = pool.StrictAliasJSON([]byte(out), &p); e != nil {
		t.Fatal(e)
	}
	if p.Token == "" {
		t.Fatal("preview token missing")
	}
	os.WriteFile(preview, []byte(out), 0600)
	after, _ = json.Marshal(poolFileSnapshot(t, dir))
	if string(before) != string(after) {
		t.Fatal("CLI preview changed pool")
	}
	for _, approval := range []string{"", strings.Repeat("0", 64)} {
		denied, _, code := runTreehouse(t, repo, home, nil, "reconcile-alias", "apply", "--request", request, "--preview", preview, "--approve-preview-sha256", approval)
		if code == 0 || strings.TrimSpace(denied) != "" {
			t.Fatal("apply bypassed exact reviewed-preview digest")
		}
	}
	out, errout, status = runTreehouse(t, repo, home, nil, "reconcile-alias", "apply", "--request", request, "--preview", preview, "--approve-preview-sha256", cmdAliasHash([]byte(out)))

	if status == 0 || strings.TrimSpace(out) != "" || !strings.Contains(errout, "legacy writer exclusion unproven") {
		t.Fatal("CLI did not fail closed without a lifecycle-owner fence")
	}
	after, _ = json.Marshal(poolFileSnapshot(t, dir))
	if string(before) != string(after) {
		t.Fatal("unfenced CLI apply changed metadata")
	}
	// Successful mutation/recovery is exercised by the pool tests with their
	// fixture fence; the production command deliberately has no such adapter.
}
