package pool

import (
	"fmt"
	"os"
	"path/filepath"
)

// AdmissionRoute is owned installation policy, not a caller's claim that old
// writers are gone. Hashes must name the independently reviewed wrapper and
// prevention-capable backing artifact at the installed owned route.
type AdmissionRoute struct {
	Wrapper       string `json:"wrapper"`
	Backing       string `json:"backing"`
	WrapperSHA256 string `json:"wrapper_sha256"`
	BackingSHA256 string `json:"backing_sha256"`
}

func admissionGatePath(pool string) string {
	return filepath.Join(pool, "treehouse-launch-admission.lock")
}

// HoldCommandAdmission holds a shared per-pool gate for the complete backing
// command lifetime. The owner wrapper bridge must retain release until its
// child exits, and call check before launch, during supervision and on return.
// It must not exec away or close the lock after merely starting the child.
func HoldCommandAdmission(pool string, route AdmissionRoute) (check func() error, release func(), err error) {
	return holdLaunchAdmission(pool, route, false)
}
func holdLaunchAdmission(pool string, route AdmissionRoute, exclusive bool) (func() error, func(), error) {
	canonical, e := filepath.EvalSymlinks(pool)
	if e != nil || !filepath.IsAbs(pool) || canonical != filepath.Clean(pool) {
		return nil, nil, fmt.Errorf("canonical per-pool admission identity required")
	}
	if !validAliasHash(route.WrapperSHA256) || !validAliasHash(route.BackingSHA256) || route.Wrapper == route.Backing {
		return nil, nil, fmt.Errorf("reviewed distinct wrapper/backing route required")
	}
	expected := map[string]string{route.Wrapper: route.WrapperSHA256, route.Backing: route.BackingSHA256}
	identities := map[string]string{}
	for path := range expected {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return nil, nil, fmt.Errorf("owned route must be an executable regular file")
		}
		if !filepath.IsAbs(path) {
			return nil, nil, fmt.Errorf("absolute owned route required")
		}
		id, e := aliasIdentity(path)
		if e != nil {
			return nil, nil, e
		}
		identities[path] = id
	}
	poolIdentity, e := aliasIdentity(pool)
	if e != nil {
		return nil, nil, e
	}
	gatePath := admissionGatePath(pool)
	gate, e := openInspectionFile(gatePath)
	if e != nil {
		return nil, nil, fmt.Errorf("existing owner-provisioned per-pool admission gate required")
	}
	good := false
	defer func() {
		if !good {
			gate.Close()
		}
	}()
	info, e := gate.Stat()
	if e != nil || info.Mode().Perm() != 0600 {
		return nil, nil, fmt.Errorf("private admission gate required")
	}
	gateIdentity, e := aliasIdentity(gatePath)
	if e != nil {
		return nil, nil, e
	}
	if exclusive {
		e = tryLockFile(gate)
	} else {
		e = trySharedAdmissionLock(gate)
	}
	if e != nil {
		return nil, nil, fmt.Errorf("per-pool launch admission busy; wait for voluntary drain")
	}
	closed := false
	release := func() {
		if !closed {
			closed = true
			unlockFile(gate)
			gate.Close()
		}
	}
	check := func() error {
		if closed {
			return fmt.Errorf("launch admission no longer held")
		}
		id, e := aliasIdentity(pool)
		if e != nil || id != poolIdentity {
			return fmt.Errorf("pool admission identity changed")
		}
		id, e = aliasIdentity(gatePath)
		if e != nil || id != gateIdentity {
			return fmt.Errorf("named admission gate changed")
		}
		held, e := gate.Stat()
		named, ne := os.Lstat(gatePath)
		if e != nil || ne != nil || !os.SameFile(held, named) {
			return fmt.Errorf("admission handle no longer names gate")
		}
		for path, hash := range expected {
			id, e := aliasIdentity(path)
			if e != nil || id != identities[path] {
				return fmt.Errorf("owned route identity changed")
			}
			data, e := readInspectionFile(path, 64<<20)
			if e != nil || aliasHash(data) != hash {
				return fmt.Errorf("owned wrapper/prevention artifact changed")
			}
		}
		return nil
	}
	if e = check(); e != nil {
		release()
		return nil, nil, e
	}
	good = true
	return check, release, nil
}

// RepairAdmissionFence combines launch-owner maintenance quiescence with the
// exclusive side of the wrapper gate. Quiescence must pause/control every owned
// launcher and prove voluntary pre-gate legacy drain, including pool-lock
// waiters; a snapshot, asserted boolean or gate acquired after old launches is
// not such a proof. Unknown/foreign writers must make that owner return error.
// This adapter has no process discovery, signal, kill, key or state-write path.
func RepairAdmissionFence(route AdmissionRoute, quiescence AliasWriterFence) AliasWriterFence {
	return func(r AliasRequest) (func() error, func(), error) {
		ownerCheck, ownerRelease, e := holdAliasWriterFence(r, quiescence)
		if e != nil {
			return nil, nil, e
		}
		gateCheck, gateRelease, e := holdLaunchAdmission(r.Pool, route, true)
		if e != nil {
			ownerRelease()
			return nil, nil, e
		}
		released := false
		release := func() {
			if !released {
				released = true
				gateRelease()
				ownerRelease()
			}
		}
		check := func() error {
			if e := ownerCheck(); e != nil {
				return e
			}
			return gateCheck()
		}
		if e = check(); e != nil {
			release()
			return nil, nil, e
		}
		return check, release, nil
	}
}
