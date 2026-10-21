package cmd

import (
	"fmt"
	"github.com/kunchenguid/treehouse/v3/internal/config"
	"github.com/kunchenguid/treehouse/v3/internal/pool"
	"github.com/kunchenguid/treehouse/v3/internal/vcs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func verifyAdmissionChild(cmd *cobra.Command) error {
	inherited := os.Getenv("TREEHOUSE_INHERITED_ADMISSION")
	if inherited == "" {
		// The bridge verifies its own route and holds the locks before dispatch.
		// Reconciliation entry points are independently read-only or require an
		// injected writer fence. Help/version never execute this lifecycle hook.
		if cmd == launchAdmittedCmd || cmd == reconcileAliasCmd || cmd.Parent() == reconcileAliasCmd || cmd.Name() == "init" || isOutputOnlyCompletion(cmd) {
			return nil
		}
		// Return and destroy resolve explicit targets independently of cwd. Check
		// those paths before any lifecycle resolver can read/heal pool state.
		args := cmd.Flags().Args()
		target := ""
		if cmd == destroyCmd && len(args) > 0 {
			target = args[0]
		} else if cmd == returnCmd && !returnAll {
			var e error
			target, e = resolveWorktreePath(args)
			if e != nil {
				return e
			}
		}
		if target != "" {
			resolved, e := rejectDirectAdmissionTarget(target)
			if e != nil || resolved {
				return e
			}
		}
		repo, e := vcs.FindMainRepoRoot()
		if e != nil {
			return nil
		}
		return rejectDirectAdmissionRepo(repo)
	}
	if os.Getenv("TREEHOUSE_INHERITED_ADMISSION") != "v1:3:4" {
		return fmt.Errorf("invalid inherited admission handoff")
	}
	repo, e := vcs.FindMainRepoRoot()
	if e != nil {
		return e
	}
	cfg, e := config.Load(repo)
	if e != nil {
		return e
	}
	dir, e := config.ResolvePoolDir(repo, config.ResolveRoot(rootFlag, cfg))
	if e != nil {
		return e
	}
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		return e
	}
	p, policyCheck, e := pool.ReadBridgePolicy(dir)
	if e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	exe, e = filepath.EvalSymlinks(exe)
	if e != nil || exe != p.Route.Backing {
		return fmt.Errorf("child backing route mismatch")
	}
	// Fixed descriptors are supplied by exec.Cmd.ExtraFiles, not arbitrary names.
	gate, owner := os.NewFile(3, "admission"), os.NewFile(4, "owner")
	check, e := pool.VerifyInheritedLaunch(dir, p.Route, gate, owner)
	if e != nil {
		return e
	}
	// Keep references alive for the process lifetime; os.File finalizers must not
	// close these descriptions after this function returns.
	admissionChildFiles = []*os.File{gate, owner}
	markAdmissionHandlesCloseOnExec()
	if e = policyCheck(); e != nil {
		return e
	}
	admissionChildCheck = func() error {
		if e := policyCheck(); e != nil {
			return e
		}
		return check()
	}
	return admissionChildCheck()
}

var admissionChildFiles []*os.File

var admissionChildCheck func() error

// Policy presence, including malformed or symlinked policy, closes the direct
// backing route. These checks never call state readers or lifecycle recovery.
func rejectDirectAdmissionPool(dir string) error {
	if _, e := os.Lstat(filepath.Join(dir, "treehouse-launch-policy.json")); e == nil || !os.IsNotExist(e) {
		return fmt.Errorf("installed pool requires admitted launch with inherited lock handles")
	}
	return nil
}

func rejectDirectAdmissionRepo(repo string) error {
	cfg, e := config.LoadForInspection(repo)
	if e != nil {
		return e
	}
	dir, e := config.ResolvePoolDir(repo, config.ResolveRoot(rootFlag, cfg))
	if e != nil {
		return e
	}
	return rejectDirectAdmissionPool(dir)
}

func rejectDirectAdmissionTarget(target string) (bool, error) {
	abs, e := filepath.Abs(target)
	if e != nil {
		return false, e
	}
	paths := []string{abs}
	if physical, e := filepath.EvalSymlinks(abs); e == nil && physical != abs {
		paths = append(paths, physical)
	}
	for _, path := range paths {
		// Destroy --all accepts a pool itself; individual worktrees use the
		// standard two-level layout even when their marker is damaged.
		for _, dir := range []string{path, filepath.Dir(filepath.Dir(path))} {
			if e := rejectDirectAdmissionPool(dir); e != nil {
				return true, e
			}
			if pool.IsPoolDir(dir) {
				return true, nil
			}
		}
	}
	// Custom-layout worktrees use the target repository's configured pool.
	if repo, e := vcs.FindMainRepoRootFrom(abs); e == nil {
		return true, rejectDirectAdmissionRepo(repo)
	}
	return false, nil
}

// Cobra owns this generated subtree. Exempt only that actual root child and
// its descendants, never a lifecycle command merely containing completion text.
func isOutputOnlyCompletion(cmd *cobra.Command) bool {
	root := cmd.Root()
	completion, _, e := root.Find([]string{"completion"})
	if e != nil || completion == root || completion.Parent() != root || completion.Name() != "completion" {
		return false
	}
	for current := cmd; current != nil && current != root; current = current.Parent() {
		if current == completion {
			return true
		}
	}
	return false
}
