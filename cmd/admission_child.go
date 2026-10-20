package cmd

import (
	"fmt"
	"github.com/kunchenguid/treehouse/v3/internal/config"
	"github.com/kunchenguid/treehouse/v3/internal/pool"
	"github.com/kunchenguid/treehouse/v3/internal/vcs"
	"os"
	"path/filepath"
)

func verifyAdmissionChild() error {
	if os.Getenv("TREEHOUSE_INHERITED_ADMISSION") == "" {
		return nil
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
