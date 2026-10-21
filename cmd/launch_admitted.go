package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kunchenguid/treehouse/v3/internal/config"
	"github.com/kunchenguid/treehouse/v3/internal/pool"
	"github.com/kunchenguid/treehouse/v3/internal/vcs"
	"github.com/spf13/cobra"
)

var launchAdmittedCmd = &cobra.Command{Use: "launch-admitted --guarded-root ROOT -- COMMAND", DisableFlagParsing: true, RunE: runLaunchAdmitted}

func init() { rootCmd.AddCommand(launchAdmittedCmd) }
func runLaunchAdmitted(cmd *cobra.Command, args []string) error {
	if len(args) < 6 || args[0] != "--guarded-root" || args[2] != "--selected-pool" || args[4] != "--" {
		return fmt.Errorf("guarded wrapper root and original command required")
	}
	guarded, e := filepath.EvalSymlinks(args[1])
	if e != nil || guarded != filepath.Clean(args[1]) {
		return fmt.Errorf("canonical guarded root required")
	}
	selected := args[3]
	if selected == "" || filepath.Base(selected) != selected || selected == "." {
		return fmt.Errorf("exact selected pool name required")
	}
	raw := args[5:]
	if len(raw) == 0 {
		return fmt.Errorf("explicit admitted command required")
	}
	// Resolve the effective root using the owning config/VCS seam. No state
	// reader or lifecycle command runs before admission. Preserve original argv.
	root := ""
	for i := 0; i < len(raw); i++ {
		if raw[i] == "--" {
			break
		}
		if strings.HasPrefix(raw[i], "--root=") {
			root = strings.TrimPrefix(raw[i], "--root=")
		}
		if raw[i] == "--root" {
			i++
			if i == len(raw) {
				return fmt.Errorf("missing root value")
			}
			root = raw[i]
		}
	}
	repo, e := vcs.FindMainRepoRoot()
	if e != nil {
		return e
	}
	cfg, e := config.Load(repo)
	if e != nil {
		return e
	}
	dir, e := config.ResolvePoolDir(repo, config.ResolveRoot(root, cfg))
	if e != nil {
		return e
	}
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		return e
	}
	if filepath.Dir(dir) != guarded {
		return fmt.Errorf("effective pool escaped external-storage guard")
	}
	targetCommand, _, findErr := cmd.Root().Find(raw)
	if findErr != nil {
		return findErr
	}
	if targetCommand.Name() == "launch-admitted" || targetCommand.Name() == "update" {
		return fmt.Errorf("recursive admission and general self-update are forbidden")
	}

	if filepath.Base(dir) != selected {
		if raw[0] == "reconcile-alias" {
			return fmt.Errorf("repair request outside selected admission pool")
		}
		// No other pool gains a new policy or gate requirement. This is the same
		// guarded backing dispatch, with exact child status/signal preservation.
		return execUnselectedAdmission(raw)
	}
	policy, policyCheck, e := pool.ReadBridgePolicy(dir)
	if e != nil {
		return e
	}
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	executable, e = filepath.EvalSymlinks(executable)
	if e != nil || executable != policy.Route.Backing {
		return fmt.Errorf("bridge is not installed owned backing")
	}
	repair := len(raw) > 1 && raw[0] == "reconcile-alias" && (raw[1] == "apply" || raw[1] == "rollback")
	if repair {
		owner := func(r pool.AliasRequest) (func() error, func(), error) {
			if r.Pool != dir {
				return nil, nil, fmt.Errorf("foreign repair pool")
			}
			check, release, e := pool.HoldLaunchOwner(dir, true)
			if e != nil {
				return nil, nil, e
			}
			combined := func() error {
				if e := policyCheck(); e != nil {
					return e
				}
				return check()
			}
			if e = combined(); e != nil {
				release()
				return nil, nil, e
			}
			return combined, release, nil
		}
		fence := pool.RepairAdmissionFence(policy.Route, owner)
		handler := newReconcileAliasCommand(fence, dir)
		handler.SetArgs(raw[1:])
		handler.SetOut(cmd.OutOrStdout())
		handler.SetErr(cmd.ErrOrStderr())
		return handler.Execute()
	}
	ownerCheck, ownerRelease, e := pool.HoldLaunchOwner(dir, false)
	if e != nil {
		return e
	}
	defer ownerRelease()
	gateCheck, gateRelease, e := pool.HoldCommandAdmission(dir, policy.Route)
	if e != nil {
		return e
	}
	defer gateRelease()
	check := func() error {
		if e := policyCheck(); e != nil {
			return e
		}
		if e := ownerCheck(); e != nil {
			return e
		}
		return gateCheck()
	}
	if e = check(); e != nil {
		return e
	}
	// Retain both shared holds for the complete child lifetime. On ownership
	// loss preserve the child and wait; never kill a foreign actor or detach it.
	inherited, e := pool.InheritedLaunchHandles(dir)
	if e != nil {
		return e
	}
	defer func() {
		for _, f := range inherited {
			f.Close()
		}
	}()
	child := exec.Command(policy.Route.Backing, raw...)
	child.ExtraFiles = inherited
	child.Env = append(os.Environ(), "TREEHOUSE_INHERITED_ADMISSION=v1:3:4")
	child.Stdin = cmd.InOrStdin()
	child.Stdout = cmd.OutOrStdout()
	child.Stderr = cmd.ErrOrStderr()
	if e = child.Start(); e != nil {
		return e
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	var lost error
	for {
		select {
		case e = <-done:
			if lost != nil {
				return lost
			}
			if err := check(); err != nil {
				return err
			}
			signal.Stop(signals)
			if e != nil {
				return admittedChildExit(e)
			}
			return e
		case sig := <-signals:
			_ = child.Process.Signal(sig) // Only the exact child started by this bridge.
		case <-ticker.C:
			if err := check(); err != nil {
				lost = err
			}
		}
	}
}
