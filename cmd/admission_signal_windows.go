//go:build windows

package cmd

import "fmt"

func markAdmissionHandlesCloseOnExec() {}
func admittedChildExit(e error) error  { return e }

func execUnselectedAdmission([]string) error {
	return fmt.Errorf("guarded macOS wrapper dispatch unsupported on Windows")
}
