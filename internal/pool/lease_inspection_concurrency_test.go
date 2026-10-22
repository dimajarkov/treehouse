package pool

import (
	"os"
	"sync"
	"testing"
)

func TestInspectionReadersCoexistWithoutAdmittingWriter(t *testing.T) {
	dir, path, expected := inspectionFixture(t)
	before := snapshotPoolFiles(t, dir)
	held, err := openInspectionFile(lockFilePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err = tryReadLockFile(held); err != nil {
		t.Fatal(err)
	}
	defer unlockFile(held)
	writer, err := openInspectionFile(lockFilePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err = tryLockFile(writer); err == nil {
		unlockFile(writer)
		t.Fatal("exclusive writer entered a reader-held lock")
	}
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := InspectLease(dir, path)
			if err != nil {
				t.Errorf("read-only inspectors must coexist: %v", err)
				return
			}
			if got.LeaseID != expected.LeaseID || got.LeaseHolder != expected.LeaseHolder {
				t.Error("lease identity changed")
			}
		}()
	}
	wg.Wait()
	assertPoolUnchanged(t, dir, before)
}

func TestInspectLeaseDeniesNonregularStateFiles(t *testing.T) {
	for _, name := range []string{"state", "key", "lock"} {
		t.Run(name, func(t *testing.T) {
			dir, path, _ := inspectionFixture(t)
			file := map[string]string{"state": stateFilePath(dir), "key": stateKeyPath(dir), "lock": lockFilePath(dir)}[name]
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(file, 0700); err != nil {
				t.Fatal(err)
			}
			before := snapshotPoolFiles(t, dir)
			if _, err := InspectLease(dir, path); err == nil {
				t.Fatal("nonregular observation admitted")
			}
			assertPoolUnchanged(t, dir, before)
		})
	}
}
