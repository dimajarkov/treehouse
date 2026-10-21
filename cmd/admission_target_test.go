package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectBackingGuardUsesTargetPool(t *testing.T) {
	repo, home := setupTestRepo(t)
	out, stderr, code := runTreehouse(t, repo, home, nil, "get", "--lease", "--lease-holder", "synthetic-target-owner", "--json")
	if code != 0 {
		t.Fatal(stderr)
	}
	var lease leaseJSONResult
	if e := json.Unmarshal([]byte(out), &lease); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Dir(filepath.Dir(lease.Path))
	statePath := filepath.Join(dir, "treehouse-state.json")
	before, e := os.ReadFile(statePath)
	if e != nil {
		t.Fatal(e)
	}
	// An unrelated repository has a different pool under this same home.
	unrelated, _ := setupTestRepo(t)
	outside := t.TempDir()
	alias := filepath.Join(t.TempDir(), "target-alias")
	if e := os.Symlink(lease.Path, alias); e != nil {
		t.Skipf("symlink unavailable: %v", e)
	}
	policy := filepath.Join(dir, "treehouse-launch-policy.json")
	for _, policyKind := range []string{"private", "malformed", "symlink"} {
		t.Run(policyKind, func(t *testing.T) {
			if policyKind == "symlink" {
				missing := filepath.Join(t.TempDir(), "missing-policy")
				if e := os.Symlink(missing, policy); e != nil {
					t.Fatal(e)
				}
			} else {
				content := []byte(`{"version":"treehouse.launch-owner.v1"}`)
				if policyKind == "malformed" {
					content = []byte(`{`)
				}
				if e := os.WriteFile(policy, content, 0600); e != nil {
					t.Fatal(e)
				}
			}
			defer os.Remove(policy)
			for _, cwd := range []string{outside, unrelated} {
				for _, journey := range []struct {
					name string
					args []string
					env  []string
				}{
					{"return-path", []string{"return", lease.Path}, nil},
					{"return-alias", []string{"return", alias}, nil},
					{"return-environment", []string{"return"}, []string{"TREEHOUSE_DIR=" + lease.Path}},
					{"destroy-path", []string{"destroy", lease.Path, "--yes"}, nil},
					{"destroy-pool", []string{"destroy", dir, "--all", "--yes"}, nil},
				} {
					t.Run(filepath.Base(cwd)+"/"+journey.name, func(t *testing.T) {
						command := exec.Command(treehouseBin, journey.args...)
						command.Dir = cwd
						command.Env = buildEnv(home, journey.env...)
						result, e := command.CombinedOutput()
						if e == nil || !strings.Contains(string(result), "requires admitted launch") {
							t.Fatalf("direct target admission bypassed: %v %s", e, result)
						}
						after, e := os.ReadFile(statePath)
						if e != nil || !bytes.Equal(before, after) {
							t.Fatal("direct refused command changed state")
						}
						if _, e = os.Stat(lease.Path); e != nil {
							t.Fatal("direct refused command changed checkout")
						}
					})
				}
			}
		})
	}
	// Unselected pools retain direct command behavior.
	_, stderr, code = runTreehouse(t, repo, home, nil, "status", "--json")
	if code != 0 {
		t.Fatalf("unprovisioned pool lost direct behavior: %s", stderr)
	}
}
