//go:build !windows

package cmd

import (
	"bytes"
	"encoding/json"
	"github.com/kunchenguid/treehouse/v3/internal/pool"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCopiedWrapperBridgePreviewApplyAndCooperativeDrain(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("copied installed wrapper uses macOS stat syntax; lock adapter tested separately")
	}
	repo, home := setupTestRepo(t)
	home, _ = filepath.EvalSymlinks(home)
	out, stderr, code := runTreehouse(t, repo, home, nil, "get", "--lease", "--lease-holder", "synthetic-wrapper-owner", "--json")
	if code != 0 {
		t.Fatal(stderr)
	}
	var lease leaseJSONResult
	json.Unmarshal([]byte(out), &lease)
	parent := filepath.Join(t.TempDir(), "external-treehouse")
	if e := os.Rename(filepath.Join(home, ".treehouse"), parent); e != nil {
		t.Fatal(e)
	}
	parent, _ = filepath.EvalSymlinks(parent)
	if e := os.Symlink(parent, filepath.Join(home, ".treehouse")); e != nil {
		t.Fatal(e)
	}
	target, _ := filepath.EvalSymlinks(lease.Path)
	dir := filepath.Dir(filepath.Dir(target))
	state, e := pool.ReadState(dir)
	if e != nil {
		t.Fatal(e)
	}
	// ReadState may discover the physical alias in this moved fixture. Build
	// exactly the controlled two-row synthetic state before any bridge proof.
	k := state.Worktrees[0]
	k.Path = lease.Path
	shadow := k
	shadow.Path = target
	shadow.Leased = false
	shadow.LeaseID = ""
	shadow.LeaseHolder = ""
	shadow.LeasedAt = time.Time{}
	if e = pool.WriteState(dir, pool.State{Worktrees: []pool.WorktreeEntry{k, shadow}}); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "treehouse-state.json"))
	pool.StrictAliasJSON(before, &state)
	backing := filepath.Join(home, ".local", "libexec", "treehouse-bin")
	os.MkdirAll(filepath.Dir(backing), 0700)
	bin, _ := os.ReadFile(treehouseBin)
	os.WriteFile(backing, bin, 0700)
	wrapper := filepath.Join(home, ".local", "bin", "treehouse")
	os.MkdirAll(filepath.Dir(wrapper), 0700)
	source, e := os.ReadFile("../owner-wrapper/treehouse.sh")
	if e != nil {
		t.Fatal(e)
	}
	statStub := filepath.Join(t.TempDir(), "synthetic-stat")
	os.WriteFile(statStub, []byte("#!/bin/sh\nif [ -n \"${SYNTHETIC_SAME_DEVICE:-}\" ]; then echo 1; elif [ \"$1\" = -L ]; then echo 2; else echo 1; fi\n"), 0700)
	draft := strings.Replace(string(source), "EXPECTED=\"/Volumes/OWC Envoy Ultra/20_PROJECTS/Development/Treehouse\"", "EXPECTED=\""+parent+"\"", 1)
	draft = strings.ReplaceAll(draft, "--selected-pool arena-crm-1adf4e", "--selected-pool "+filepath.Base(dir))
	draft = strings.ReplaceAll(draft, "/usr/bin/stat", statStub)
	os.WriteFile(wrapper, []byte(draft), 0700)
	route := pool.AdmissionRoute{Wrapper: wrapper, Backing: backing, WrapperSHA256: cmdAliasHash([]byte(draft)), BackingSHA256: cmdAliasHash(bin)}
	policy := pool.BridgePolicy{Version: "treehouse.launch-owner.v1", Pool: dir, Route: route, Owners: []string{"synthetic-controlled-launcher"}}
	pb, _ := json.Marshal(policy)
	os.WriteFile(filepath.Join(dir, "treehouse-launch-policy.json"), pb, 0600)
	for _, name := range []string{"treehouse-launch-owner.lock", "treehouse-launch-admission.lock"} {
		os.WriteFile(filepath.Join(dir, name), nil, 0600)
	}
	kb, _ := json.Marshal(state.Worktrees[0])
	sb, _ := json.Marshal(state.Worktrees[1])
	req := pool.AliasRequest{Pool: dir, Target: target, Name: k.Name, LeaseID: k.LeaseID, Holder: k.LeaseHolder, LeasedAt: k.LeasedAt, StateHash: cmdAliasHash(before), KeeperHash: cmdAliasHash(kb), ShadowHash: cmdAliasHash(sb)}
	request := filepath.Join(t.TempDir(), "request.json")
	rb, _ := json.Marshal(req)
	os.WriteFile(request, rb, 0600)
	run := func(extra []string, args ...string) (string, string, int) {
		c := exec.Command(wrapper, args...)
		c.Dir = repo
		c.Env = buildEnv(home, extra...)
		var o, b bytes.Buffer
		c.Stdout = &o
		c.Stderr = &b
		err := c.Run()
		n := 0
		if err != nil {
			n = err.(*exec.ExitError).ExitCode()
		}
		return o.String(), b.String(), n
	}
	out, stderr, code = run(nil, "reconcile-alias", "preview", "--request", request)
	if code != 0 {
		t.Fatalf("copied wrapper preview: %s", stderr)
	}
	preview := filepath.Join(t.TempDir(), "preview.json")
	os.WriteFile(preview, []byte(out), 0600)
	digest := cmdAliasHash([]byte(out))
	applyArgs := []string{"reconcile-alias", "apply", "--request", request, "--preview", preview, "--approve-preview-sha256", digest}
	// A pre-gate cooperative legacy actor can already be waiting on the pool
	// lock. Its owner hold prevents maintenance even if admission is unused.
	_, voluntary, e := pool.HoldLaunchOwner(dir, false)
	if e != nil {
		t.Fatal(e)
	}
	denied, reason, status := run(nil, applyArgs...)
	if status == 0 || denied != "" || !strings.Contains(reason, "not drained") {
		t.Fatalf("legacy waiter admitted: %s", reason)
	}
	voluntary()
	out, stderr, code = run(nil, applyArgs...)
	if code != 0 {
		t.Fatalf("copied wrapper apply: %s", stderr)
	}
	var result pool.AliasResult
	if e = json.Unmarshal([]byte(out), &result); e != nil || result.Outcome != "confirmed" {
		t.Fatalf("apply receipt %s %v", out, e)
	}
	if _, e = pool.InspectLease(dir, target); e != nil {
		t.Fatal(e)
	}
	out, stderr, code = run(nil, "reconcile-alias", "rollback", "--request", request, "--transaction", result.Transaction)
	if code != 0 {
		t.Fatalf("copied wrapper rollback: %s", stderr)
	}
	restored, _ := os.ReadFile(filepath.Join(dir, "treehouse-state.json"))
	if !bytes.Equal(before, restored) {
		t.Fatal("rollback did not restore original bytes")
	}
	// Every original external path/volume guard remains ahead of admission.
	for _, kind := range []string{"same-device", "missing-logical", "wrong-logical", "missing-external", "effective-root-escape", "unknown-owner-policy"} {
		t.Run(kind, func(t *testing.T) {
			var env []string
			args := []string{"reconcile-alias", "preview", "--request", request}
			restore := func() {}
			switch kind {
			case "same-device":
				env = []string{"SYNTHETIC_SAME_DEVICE=1"}
			case "missing-logical":
				os.Remove(filepath.Join(home, ".treehouse"))
				restore = func() { os.Symlink(parent, filepath.Join(home, ".treehouse")) }
			case "wrong-logical":
				os.Remove(filepath.Join(home, ".treehouse"))
				os.Symlink(t.TempDir(), filepath.Join(home, ".treehouse"))
				restore = func() {
					os.Remove(filepath.Join(home, ".treehouse"))
					os.Symlink(parent, filepath.Join(home, ".treehouse"))
				}
			case "missing-external":
				os.Rename(parent, parent+".retained")
				restore = func() { os.Rename(parent+".retained", parent) }
			case "effective-root-escape":
				env = []string{"TREEHOUSE_ROOT=" + t.TempDir()}
			case "unknown-owner-policy":
				os.Rename(filepath.Join(dir, "treehouse-launch-policy.json"), filepath.Join(dir, "policy.retained"))
				restore = func() {
					os.Rename(filepath.Join(dir, "policy.retained"), filepath.Join(dir, "treehouse-launch-policy.json"))
				}
			}
			defer restore()
			out, _, status := run(env, args...)
			if status == 0 || out != "" {
				t.Fatal("guard/unknown owner bypassed")
			}
		})
	}

	// A sibling pool keeps its original guarded dispatch without provisioning
	// admission policy, touching selected metadata or taking selected-pool locks.
	otherRepo, _ := setupTestRepo(t)
	_, otherErr, otherCode := runTreehouse(t, otherRepo, home, nil, "get", "--lease", "--lease-holder", "synthetic-sibling", "--json")
	if otherCode != 0 {
		t.Fatal(otherErr)
	}
	selectedBefore, _ := os.ReadFile(filepath.Join(dir, "treehouse-state.json"))
	sibling := exec.Command(wrapper, "status", "--json")
	sibling.Dir = otherRepo
	sibling.Env = buildEnv(home)
	if b, e := sibling.CombinedOutput(); e != nil {
		t.Fatalf("sibling pool dispatch changed: %s", b)
	}
	selectedAfter, _ := os.ReadFile(filepath.Join(dir, "treehouse-state.json"))
	if !bytes.Equal(selectedBefore, selectedAfter) {
		t.Fatal("sibling command changed selected pool")
	}

	// Sibling-pool dispatch must remain exec, not a supervisor that can orphan
	// the backing command when only the wrapper PID receives termination.
	siblingReady := filepath.Join(t.TempDir(), "ready")
	siblingRelease := filepath.Join(t.TempDir(), "release")
	siblingLong := exec.Command(wrapper, "get")
	siblingLong.Dir = otherRepo
	siblingLong.Env = buildEnv(home, "SHELL="+waitShellBin, "TREEHOUSE_TEST_READY="+siblingReady, "TREEHOUSE_TEST_RELEASE="+siblingRelease)
	siblingLog, e := os.CreateTemp(t.TempDir(), "sibling-log")
	if e != nil {
		t.Fatal(e)
	}
	defer siblingLog.Close()
	siblingLong.Stdout = siblingLog
	siblingLong.Stderr = siblingLog
	if e = siblingLong.Start(); e != nil {
		t.Fatal(e)
	}
	defer os.WriteFile(siblingRelease, nil, 0600)
	siblingDeadline := time.Now().Add(15 * time.Second)
	for {
		if b, _ := os.ReadFile(siblingReady); len(b) > 0 {
			break
		}
		if time.Now().After(siblingDeadline) {
			siblingLong.Process.Kill()
			siblingLong.Wait()
			t.Fatal("owned sibling not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	siblingLong.Process.Signal(syscall.SIGTERM)
	siblingErr := siblingLong.Wait()
	siblingExit, ok := siblingErr.(*exec.ExitError)
	if !ok {
		t.Fatal("sibling termination not preserved")
	}
	siblingStatus := siblingExit.Sys().(syscall.WaitStatus)
	if !siblingStatus.Signaled() || siblingStatus.Signal() != syscall.SIGTERM {
		t.Fatal("sibling SIGTERM did not terminate backing PID")
	}
	os.WriteFile(siblingRelease, nil, 0600)
	// Owned abrupt-supervisor-loss proof. The actual backing child must keep
	// both kernel locks after its supervising wrapper is killed.
	ready := filepath.Join(t.TempDir(), "child-pid")
	releaseFile := filepath.Join(t.TempDir(), "release")
	// Use the existing compiled wait-shell, which has a bounded voluntary exit.
	c := exec.Command(wrapper, "get")
	c.Dir = repo
	c.Env = buildEnv(home, "SHELL="+waitShellBin, "TREEHOUSE_TEST_READY="+ready, "TREEHOUSE_TEST_RELEASE="+releaseFile)
	output, e := os.CreateTemp(t.TempDir(), "owned-command-log")
	if e != nil {
		t.Fatal(e)
	}
	defer output.Close()
	c.Stdout = output
	c.Stderr = output
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	defer os.WriteFile(releaseFile, nil, 0600)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if b, _ := os.ReadFile(ready); len(b) > 0 {
			break
		}
		if time.Now().After(deadline) {
			c.Process.Kill()
			c.Wait()
			b, _ := os.ReadFile(output.Name())
			t.Fatalf("owned child not ready: %s", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e = c.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	c.Wait() // Exact task-owned supervisor only.
	if _, done, e := pool.HoldLaunchOwner(dir, true); e == nil {
		done()
		t.Fatal("SIGKILL of supervisor released surviving child's owner hold")
	}
	if _, done, e := pool.HoldCommandAdmission(dir, route); e != nil {
		t.Fatal(e)
	} else {
		done()
	}
	os.WriteFile(releaseFile, nil, 0600)
	deadline = time.Now().Add(15 * time.Second)
	for {
		if _, done, e := pool.HoldLaunchOwner(dir, true); e == nil {
			done()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not voluntarily release inherited hold")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Normal nonzero exit status remains the backing command's status.
	directOut, directErr, directCode := runTreehouse(t, repo, home, nil, "unknown-synthetic-command")
	_ = directOut
	_ = directErr
	_, _, wrappedCode := run(nil, "unknown-synthetic-command")
	if wrappedCode != directCode {
		t.Fatal("backing exit status changed")
	}
	// A normal termination request is forwarded only to the exact started child;
	// the supervisor mirrors the child's terminal signal after it exits.
	ready2 := filepath.Join(t.TempDir(), "ready")
	release2 := filepath.Join(t.TempDir(), "release")
	signalShell := filepath.Join(t.TempDir(), "owned-signal-shell")
	os.WriteFile(signalShell, []byte("#!/bin/sh\necho $$ > \"$TREEHOUSE_TEST_READY\"\nwhile [ ! -e \"$TREEHOUSE_TEST_RELEASE\" ]; do /bin/sleep 0.02; done\n"), 0700)
	c2 := exec.Command(wrapper, "get")
	c2.Dir = repo
	c2.Env = buildEnv(home, "SHELL="+signalShell, "TREEHOUSE_TEST_READY="+ready2, "TREEHOUSE_TEST_RELEASE="+release2)
	c2.Stdout = output
	c2.Stderr = output
	if e = c2.Start(); e != nil {
		t.Fatal(e)
	}
	defer os.WriteFile(release2, nil, 0600)
	deadline = time.Now().Add(15 * time.Second)
	for {
		if b, _ := os.ReadFile(ready2); len(b) > 0 {
			break
		}
		if time.Now().After(deadline) {
			c2.Process.Kill()
			c2.Wait()
			t.Fatal("signal fixture not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	c2.Process.Signal(syscall.SIGTERM)
	err := c2.Wait()
	exit, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatal("signal exit missing")
	}
	status2 := exit.Sys().(syscall.WaitStatus)
	if !status2.Signaled() || status2.Signal() != syscall.SIGTERM {
		t.Fatalf("terminal signal not preserved: %v", status2)
	}

	shellPIDBytes, _ := os.ReadFile(ready2)
	shellPID, e := strconv.Atoi(strings.TrimSpace(string(shellPIDBytes)))
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(release2, nil, 0600)
	// The shell is an owned grandchild after backing SIGTERM. Wait for its
	// voluntary exit before TempDir cleanup can remove the release predicate.
	deadline = time.Now().Add(10 * time.Second)
	for syscall.Kill(shellPID, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatal("owned signal fixture did not voluntarily exit")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Log("copied-wrapper preview/apply/rollback passed; cooperative pre-gate waiter blocked apply; external guards preserved with synthetic device seam")
}

func TestAdmissionPreservesArbitraryChildExitStatus(t *testing.T) {
	e := exec.Command("/bin/sh", "-c", "exit 17").Run()
	if ExitCode(admittedChildExit(e)) != 17 {
		t.Fatal("child exit status was normalized")
	}
}
