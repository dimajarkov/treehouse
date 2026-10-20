//go:build windows

package pool

import (
	"fmt"
	"os"
)

func trySharedAdmissionLock(*os.File) error {
	return fmt.Errorf("launch admission unsupported on Windows pending owner/ACL proof")
}
