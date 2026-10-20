//go:build windows

package cmd

func markAdmissionHandlesCloseOnExec() {}
func admittedChildExit(e error) error  { return e }
