//go:build !windows

package pool

import (
	"fmt"
	"os"
	"syscall"
)

// Owner identity and stable filesystem ID are token-bound. No key hash or
// mtime substitutes for inode identity, and no chmod/chown repairs are made.
func aliasFileIdentity(i os.FileInfo) (string, error) {
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return "", fmt.Errorf("transaction requires current-user-owned files")
	}
	return fmt.Sprintf("%d:%d:%d:%d:%o", st.Dev, st.Ino, st.Uid, st.Gid, i.Mode()), nil
}

func aliasStateWritable(state, pool os.FileInfo) error {
	st, ok := state.Sys().(*syscall.Stat_t)
	if !ok || st.Gid != uint32(os.Getegid()) || pool.Mode()&os.ModeSetgid != 0 {
		return fmt.Errorf("state replacement cannot preserve original group")
	}
	return nil
}
