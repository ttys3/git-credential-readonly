package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestWritePrivateFileRejectsChangedRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	revision := credentialFileRevision([]byte("original\n"))
	if err := os.WriteFile(path, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := writePrivateFileIfUnchanged(path, []byte("replacement\n"), revision)
	if !errors.Is(err, errCredentialChanged) {
		t.Fatalf("error = %v, want changed revision error", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "changed\n" {
		t.Fatalf("file = %q, want concurrent content", data)
	}
	assertNoCredentialLockFile(t, path+".lock")
}

func TestWritePrivateFileSerializesConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	initial := []byte("initial\n")
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	revision := credentialFileRevision(initial)

	start := make(chan struct{})
	results := make(chan error, 2)
	var writers sync.WaitGroup
	for _, data := range [][]byte{[]byte("writer-one\n"), []byte("writer-two\n")} {
		data := data
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			results <- writePrivateFileIfUnchanged(path, data, revision)
		}()
	}
	close(start)
	writers.Wait()
	close(results)

	successes := 0
	changed := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, errCredentialChanged):
			changed++
		default:
			t.Fatalf("unexpected write error: %v", err)
		}
	}
	if successes != 1 || changed != 1 {
		t.Fatalf("successes = %d, changed = %d; want 1 and 1", successes, changed)
	}
	assertNoCredentialLockFile(t, path+".lock")
}

func TestAcquireAdvisoryFileLockRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation commonly requires elevated privileges on Windows")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	lockPath := filepath.Join(directory, "credentials.lock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lockPath); err != nil {
		t.Fatal(err)
	}

	lock, err := acquireAdvisoryFileLock(lockPath)
	if lock != nil {
		_ = lock.Close()
		t.Fatal("symlink lock unexpectedly returned a file")
	}
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("error = %v, want unsafe lock-path error", err)
	}
}

func TestReadFileLimitedEnforcesSizeAndRegularFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "credentials")
	if err := os.WriteFile(path, []byte("123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileLimited(path, 8); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized file error = %v", err)
	}
	if _, err := readFileLimited(directory, 8); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error = %v", err)
	}
}

func assertNoCredentialLockFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential lock file remains after write: %v", err)
	}
}
