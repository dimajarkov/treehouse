//go:build !windows

package pool

import (
	"os"
	"syscall"
)

func trySharedAdmissionLock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
}
