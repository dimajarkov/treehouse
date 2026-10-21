package pool

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kunchenguid/treehouse/v3/internal/vcs"
)

// LeaseInspection proves only the current durable lease identity. It says
// nothing about process liveness, quietness, branch, source or runtime health.
type LeaseInspection struct {
	SchemaVersion string    `json:"schema_version"`
	Pool          string    `json:"pool"`
	Name          string    `json:"name"`
	Path          string    `json:"path"`
	Status        string    `json:"status"`
	LeaseID       string    `json:"lease_id"`
	LeaseHolder   string    `json:"lease_holder"`
	LeasedAt      time.Time `json:"leased_at"`
}

// Existing regular files only: inspection cannot create state, keys or locks,
// follow a substituted file symlink, or trigger automatic state recovery.
func openInspectionFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("lease inspection requires an existing regular state file")
	}
	f, err := openInspectionHandle(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) {
		f.Close()
		return nil, fmt.Errorf("lease inspection file changed during open")
	}
	return f, nil
}
func readInspectionFile(path string, limit int64) ([]byte, error) {
	f, err := openInspectionFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > limit {
		return nil, fmt.Errorf("lease inspection state exceeds its bound")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	named, namedErr := os.Lstat(path)
	if err != nil || namedErr != nil || !named.Mode().IsRegular() || !os.SameFile(info, named) || !after.ModTime().Equal(info.ModTime()) || after.Size() != info.Size() || int64(len(data)) != info.Size() || int64(len(data)) > limit {
		return nil, fmt.Errorf("lease inspection state changed during read")
	}
	return data, nil
}

// InspectLease never calls WithStateLock: that owner deliberately performs
// quarantine recovery before its callback. Use the existing lock without
// creating it, take it nonblocking, and read only the currently persisted state.
func InspectLease(poolDir, worktreePath string) (LeaseInspection, error) {
	deny := func() (LeaseInspection, error) {
		return LeaseInspection{}, fmt.Errorf("cannot corroborate one current durable lease; inspect the pool through its lifecycle owner")
	}
	if !filepath.IsAbs(worktreePath) {
		return deny()
	}
	canonical, err := filepath.EvalSymlinks(worktreePath)
	if err != nil {
		return deny()
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return deny()
	}
	canonicalPool, err := filepath.EvalSymlinks(poolDir)
	if err != nil {
		return deny()
	}
	lock, err := openInspectionFile(lockFilePath(canonicalPool))
	if err != nil {
		return deny()
	}
	defer lock.Close()
	if err = tryLockFile(lock); err != nil {
		return LeaseInspection{}, fmt.Errorf("lease inspection unavailable: existing pool lock is busy or unverifiable")
	}
	defer unlockFile(lock)
	data, err := readInspectionFile(stateFilePath(canonicalPool), 16*1024*1024)
	if err != nil {
		return deny()
	}
	key, err := readInspectionFile(stateKeyPath(canonicalPool), sha256.Size)
	if err != nil || len(key) != sha256.Size {
		return deny()
	}
	defer clear(key)
	inspection, err := inspectLeaseObservation(canonicalPool, canonical, data, key)
	if err != nil {
		return deny()
	}
	// Corroborate the named lock and unchanged observation before releasing it.
	lockInfo, lockErr := lock.Stat()
	namedLock, namedErr := os.Lstat(lockFilePath(canonicalPool))
	again, stateErr := readInspectionFile(stateFilePath(canonicalPool), 16*1024*1024)
	againKey, keyErr := readInspectionFile(stateKeyPath(canonicalPool), sha256.Size)
	currentPath, pathErr := filepath.EvalSymlinks(worktreePath)
	if lockErr != nil || namedErr != nil || !namedLock.Mode().IsRegular() || !os.SameFile(lockInfo, namedLock) || stateErr != nil || keyErr != nil || !bytes.Equal(data, again) || !bytes.Equal(key, againKey) || pathErr != nil || currentPath != canonical {
		return deny()
	}
	return inspection, nil
}

// inspectLeaseObservation validates a pinned observation while its caller owns
// the existing lock. It acquires no lock and never heals or persists state.
func inspectLeaseObservation(canonicalPool, canonical string, data, key []byte) (LeaseInspection, error) {
	deny := func() (LeaseInspection, error) {
		return LeaseInspection{}, fmt.Errorf("cannot corroborate one current durable lease; inspect the pool through its lifecycle owner")
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return deny()
	}
	var state State
	if err = json.Unmarshal(data, &state); err != nil || state.Version != stateVersion {
		return deny()
	}
	if len(key) != sha256.Size {
		return deny()
	}
	state = validateStateInventories(state, key, nil)
	var matches []WorktreeEntry
	for _, entry := range state.Worktrees {
		if !filepath.IsAbs(entry.Path) {
			continue
		}
		candidate, err := os.Stat(entry.Path)
		// Filesystem identity also catches case aliases on macOS/Windows;
		// EvalSymlinks path strings alone can split one registered checkout.
		if err == nil && os.SameFile(info, candidate) {
			matches = append(matches, entry)
		}
	}
	if len(matches) != 1 {
		return deny()
	}
	entry := matches[0]
	id, err := hex.DecodeString(entry.LeaseID)
	if !entry.Leased || entry.Destroying || entry.RecoveryError != "" || entry.RecoveryReason != "" || entry.LeaseHolder == RecoveredLeaseHolder || strings.TrimSpace(entry.LeaseHolder) == "" || strings.TrimSpace(entry.Name) == "" || entry.LeasedAt.IsZero() || err != nil || len(id) != 16 || !entry.SeedInventoryKnown {
		return deny()
	}
	for _, other := range state.Worktrees {
		if other.Name == entry.Name && other.Path != entry.Path {
			return deny()
		}
	}
	backend, err := vcs.WorktreeBackendNameChecked(canonical)
	if err != nil || backend == "" {
		return deny()
	}
	if _, err = vcs.FindMainRepoRootFrom(canonical); err != nil {
		return deny()
	}
	return LeaseInspection{SchemaVersion: "treehouse.lease-inspection.v1", Pool: canonicalPool, Name: entry.Name, Path: canonical, Status: StatusLeased, LeaseID: entry.LeaseID, LeaseHolder: entry.LeaseHolder, LeasedAt: entry.LeasedAt}, nil
}
