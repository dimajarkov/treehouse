//go:build windows

package pool

import (
	"fmt"
	"os"
)

// Reconciliation refuses Windows until equivalent owner/ACL and durable
// directory-sync guarantees have runtime proof. Read-only lease inspection
// remains independently supported on Windows.
func aliasFileIdentity(os.FileInfo) (string, error) {
	return "", fmt.Errorf("alias reconciliation is unsupported on Windows")
}

func aliasStateWritable(os.FileInfo, os.FileInfo) error {
	return fmt.Errorf("alias reconciliation is unsupported on Windows")
}
