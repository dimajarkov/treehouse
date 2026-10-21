//go:build !windows

package cmd

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func markAdmissionHandlesCloseOnExec() { syscall.CloseOnExec(3); syscall.CloseOnExec(4) }
func admittedChildExit(e error) error {
	if child, ok := e.(*exec.ExitError); ok {
		if status, ok := child.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			sig := status.Signal()
			signal.Reset(sig)
			if syscall.Kill(os.Getpid(), sig) == nil {
				for {
					time.Sleep(time.Second)
				}
			}
			return withExitCode(128+int(sig), e)
		}
		return withExitCode(child.ExitCode(), e)
	}
	return e
}

// Unselected pools retain the owner's original exec dispatch: no new parent
// can die while leaving the backing process running under a different PID.
func execUnselectedAdmission(args []string) error {
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	return syscall.Exec(executable, append([]string{executable}, args...), os.Environ())
}
