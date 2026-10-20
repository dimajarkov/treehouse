package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func poolFileSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(dir, path)
		result[relative] = fmt.Sprintf("%s:%d:%s", info.ModTime(), info.Mode(), data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestLeaseInspectionCLIReadOnlyAndPoolResolution(t *testing.T) {
	repo, home := setupTestRepo(t)
	leased, stderr, code := runTreehouse(t, repo, home, nil, "get", "--lease", "--lease-holder", "synthetic-owner", "--json")
	if code != 0 {
		t.Fatalf("fixture lease failed: %s", stderr)
	}
	var lease leaseJSONResult
	if err := json.Unmarshal([]byte(leased), &lease); err != nil {
		t.Fatal(err)
	}
	poolRoot := filepath.Join(home, ".treehouse")
	before, _ := json.Marshal(poolFileSnapshot(t, poolRoot))
	for _, cwd := range []string{repo, lease.Path} {
		stdout, stderr, code := runTreehouse(t, cwd, home, nil, "status", "--lease-path", lease.Path, "--json")
		if code != 0 {
			t.Fatalf("inspection failed: %s", stderr)
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0]["schema_version"] != "treehouse.lease-inspection.v1" || rows[0]["lease_id"] != lease.LeaseID || rows[0]["lease_holder"] != lease.LeaseHolder || rows[0]["status"] != "leased" {
			t.Fatalf("incorrect inspection: %s", stdout)
		}
		if _, exists := rows[0]["processes"]; exists {
			t.Fatal("lease-only inspection must not imply process quietness")
		}
	}
	for _, args := range [][]string{
		{"status", "--lease-path", lease.Path},
		{"status", "--lease-path", "", "--json"},
		{"status", "--lease-path", "relative/path", "--json"},
		{"status", "--lease-path", lease.Path, "--json", "unexpected-argument"},
		{"status", "--lease-path", repo, "--json"},
		{"status", "--lease-path", lease.Path, "--json", "--root", filepath.Join(home, "missing-root")},
	} {
		stdout, _, code := runTreehouse(t, repo, home, nil, args...)
		if code == 0 || strings.TrimSpace(stdout) != "" {
			t.Fatalf("uncertain inspection succeeded or exposed a partial receipt: %q (%d)", stdout, code)
		}
	}
	after, _ := json.Marshal(poolFileSnapshot(t, poolRoot))
	if string(before) != string(after) {
		t.Fatal("CLI inspection changed pool or sibling files")
	}
	if _, err := os.Stat(filepath.Join(home, "missing-root")); !os.IsNotExist(err) {
		t.Fatal("inspection created a missing pool")
	}

}
func TestLeaseInspectionSkipsUpdaterEvenWithInvalidPath(t *testing.T) {
	isolateHome(t)
	setNixStore(t, false)
	setReleaseVersion(t, "v3.1.4")
	flag := statusCmd.Flags().Lookup("lease-path")
	oldChanged, oldValue := flag.Changed, flag.Value.String()
	t.Cleanup(func() { flag.Value.Set(oldValue); flag.Changed = oldChanged })
	previous := spawnBackgroundCheck
	spawned := 0
	spawnBackgroundCheck = func(string) error { spawned++; return nil }
	defer func() { spawnBackgroundCheck = previous }()
	for _, value := range []string{"", filepath.Join(t.TempDir(), "synthetic")} {
		statusCmd.Flags().Set("lease-path", value)
		output := captureStderr(t, func() {
			func() {
				if e := rootCmd.PersistentPreRunE(statusCmd, nil); e != nil {
					t.Fatal(e)
				}
			}()
		})
		if spawned != 0 || output != "" {
			t.Fatal("read-only lease mode invoked updater")
		}
	}
}
