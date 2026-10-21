//go:build !windows

package pool

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func admissionFixture(t *testing.T) (string, AdmissionRoute) {
	t.Helper()
	dir := t.TempDir()
	dir, e := filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	wrapper, backing := filepath.Join(dir, "wrapper"), filepath.Join(dir, "backing")
	os.WriteFile(wrapper, []byte("synthetic guarded wrapper"), 0700)
	os.WriteFile(backing, []byte("synthetic reviewed prevention"), 0700)
	pool := filepath.Join(dir, "selected-pool")
	os.Mkdir(pool, 0700)
	os.WriteFile(admissionGatePath(pool), nil, 0600)
	return pool, AdmissionRoute{wrapper, backing, aliasHash(aliasRead(t, wrapper)), aliasHash(aliasRead(t, backing))}
}
func TestAdmissionSharedLifetimeAndExclusiveRepair(t *testing.T) {
	pool, route := admissionFixture(t)
	c1, r1, e := HoldCommandAdmission(pool, route)
	if e != nil {
		t.Fatal(e)
	}
	defer r1()
	_, r2, e := HoldCommandAdmission(pool, route)
	if e != nil {
		t.Fatal(e)
	}
	fence := RepairAdmissionFence(route, syntheticAliasFence)
	if _, _, e = fence(AliasRequest{Pool: pool}); e == nil {
		t.Fatal("repair entered while backing commands active")
	}
	r2()
	r1() // voluntary command completion, never process termination
	check, release, e := fence(AliasRequest{Pool: pool})
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if e = check(); e != nil {
		t.Fatal(e)
	}
	if _, _, e = HoldCommandAdmission(pool, route); e == nil {
		t.Fatal("new launch entered exclusive repair")
	}
	release()
	if e = c1(); e == nil {
		t.Fatal("released shared hold still validated")
	}
	_, done, e := HoldCommandAdmission(pool, route)
	if e != nil {
		t.Fatal(e)
	}
	done()
}
func TestAdmissionLegacyDrainAndUnknownOwnerStop(t *testing.T) {
	pool, route := admissionFixture(t)
	for _, state := range []string{"running-legacy", "queued-legacy-pool-waiter", "foreign-writer", "unknown-launch-owner"} {
		t.Run(state, func(t *testing.T) {
			pending := true
			closed := false
			owner := func(AliasRequest) (func() error, func(), error) {
				return func() error {
					if pending {
						return fmt.Errorf("synthetic owner: %s not excluded", state)
					}
					if closed {
						return fmt.Errorf("owner hold lost")
					}
					return nil
				}, func() { closed = true }, nil
			}
			if _, _, e := RepairAdmissionFence(route, owner)(AliasRequest{Pool: pool}); e == nil {
				t.Fatal("unproven pre-gate writer admitted")
			}
		})
	}
	// The owner keeps its launchers paused while the pre-gate actor voluntarily
	// exits. The gate itself cannot infer this drain; the owner lifetime supplies it.
	legacyActive := true
	held := false
	owner := func(AliasRequest) (func() error, func(), error) {
		held = true
		return func() error {
			if !held || legacyActive {
				return fmt.Errorf("owned legacy drain incomplete")
			}
			return nil
		}, func() { held = false }, nil
	}
	if _, _, e := RepairAdmissionFence(route, owner)(AliasRequest{Pool: pool}); e == nil {
		t.Fatal("active legacy writer ignored")
	}
	legacyActive = false
	check, release, e := RepairAdmissionFence(route, owner)(AliasRequest{Pool: pool})
	if e != nil {
		t.Fatal(e)
	}
	if !held {
		t.Fatal("owner quiescence not retained")
	}
	held = false
	if e = check(); e == nil {
		t.Fatal("lost owner accepted")
	}
	release()
}
func TestAdmissionRouteAndGateIdentityRemainPinned(t *testing.T) {
	for _, change := range []string{"wrapper-bytes", "backing-bytes", "wrapper-inode", "gate-inode"} {
		t.Run(change, func(t *testing.T) {
			pool, route := admissionFixture(t)
			check, release, e := RepairAdmissionFence(route, syntheticAliasFence)(AliasRequest{Pool: pool})
			if e != nil {
				t.Fatal(e)
			}
			defer release()
			path := route.Wrapper
			if change == "backing-bytes" {
				path = route.Backing
			}
			if change == "gate-inode" {
				path = admissionGatePath(pool)
			}
			if strings.HasSuffix(change, "inode") {
				b := aliasRead(t, path)
				os.Rename(path, path+".retained")
				os.WriteFile(path, b, 0600)
			} else {
				os.WriteFile(path, []byte("changed"), 0700)
			}
			if e = check(); e == nil {
				t.Fatal("route/gate change accepted")
			}
		})
	}
}
func TestAdmissionMissingGateDoesNotProvisionOrTouchForeignActor(t *testing.T) {
	pool, route := admissionFixture(t)
	os.Remove(admissionGatePath(pool))
	child := exec.Command(os.Args[0], "-test.run=^TestAdmissionForeignFixtureActor$")
	child.Env = append(os.Environ(), "TREEHOUSE_SYNTHETIC_FOREIGN_ACTOR=1")
	child.Dir = t.TempDir()
	input, e := child.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := child.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { input.Close(); child.Wait() }()
	ready := make([]byte, 1)
	if _, e = io.ReadFull(output, ready); e != nil {
		t.Fatal(e)
	}
	if _, _, e = RepairAdmissionFence(route, syntheticAliasFence)(AliasRequest{Pool: pool}); e == nil {
		t.Fatal("missing gate provisioned implicitly")
	}
	if _, e = os.Lstat(admissionGatePath(pool)); !os.IsNotExist(e) {
		t.Fatal("missing gate created")
	}
	if e = child.Process.Signal(syscall.Signal(0)); e != nil {
		t.Fatal("foreign synthetic actor changed")
	}
}
func TestAdmissionForeignFixtureActor(t *testing.T) {
	if os.Getenv("TREEHOUSE_SYNTHETIC_FOREIGN_ACTOR") != "1" {
		return
	}
	os.Stdout.Write([]byte("R"))
	io.Copy(io.Discard, os.Stdin)
}
