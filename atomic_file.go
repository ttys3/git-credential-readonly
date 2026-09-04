package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const privateFileLockTimeout = time.Second

type lockedPrivatePath struct {
	path string
	lock *os.File
}

func writePrivateFile(path string, data []byte) error {
	return writePrivateFileIfUnchanged(path, data, "")
}

func writePrivateFileIfUnchanged(path string, data []byte, expectedRevision string) error {
	resolvedPath, directory, err := preparePrivatePath(path)
	if err != nil {
		return err
	}

	lockPath := resolvedPath + ".lock"
	lockFile, err := acquireCredentialLockFile(lockPath)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = lockFile.Close()
		if !committed {
			_ = os.Remove(lockPath)
		}
	}()

	if expectedRevision != "" {
		currentRevision, err := privateFileRevision(resolvedPath)
		if err != nil {
			return err
		}
		if currentRevision != expectedRevision {
			return errCredentialChanged
		}
	}

	if err := lockFile.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict credential lock file permissions: %w", err)
	}
	if _, err := io.Copy(lockFile, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write credential lock file: %w", err)
	}
	if err := lockFile.Sync(); err != nil {
		return fmt.Errorf("sync credential lock file: %w", err)
	}
	if err := lockFile.Close(); err != nil {
		return fmt.Errorf("close credential lock file: %w", err)
	}
	if err := replaceFile(lockPath, resolvedPath); err != nil {
		return fmt.Errorf("replace credential file: %w", err)
	}
	committed = true

	// Syncing the containing directory makes the rename durable on filesystems
	// that support directory fsync. Some platforms reject it, so it is best
	// effort after the data itself has been synced.
	if directoryHandle, err := os.Open(directory); err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}

func lockPrivatePath(path string) (*lockedPrivatePath, error) {
	resolvedPath, _, err := preparePrivatePath(path)
	if err != nil {
		return nil, err
	}

	lock, err := acquireAdvisoryFileLock(resolvedPath + ".transaction-lock")
	if err != nil {
		return nil, err
	}
	return &lockedPrivatePath{path: resolvedPath, lock: lock}, nil
}

func (p *lockedPrivatePath) release() {
	if p == nil || p.lock == nil {
		return
	}
	_ = unlockPrivateFile(p.lock)
	_ = p.lock.Close()
	p.lock = nil
}

func preparePrivatePath(path string) (string, string, error) {
	resolvedPath, err := resolveCredentialWritePath(path)
	if err != nil {
		return "", "", err
	}
	directory := filepath.Dir(resolvedPath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", "", fmt.Errorf("create credential directory: %w", err)
	}
	return resolvedPath, directory, nil
}

func acquireCredentialLockFile(lockPath string) (*os.File, error) {
	deadline := time.Now().Add(privateFileLockTimeout)
	for {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create credential lock file: %w", err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: %s", errCredentialStoreLocked, lockPath)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func acquireAdvisoryFileLock(lockPath string) (*os.File, error) {
	file, err := openAdvisoryFileLock(lockPath)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(privateFileLockTimeout)
	for {
		locked, err := tryLockPrivateFile(file)
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("lock credential store: %w", err)
		}
		if locked {
			return file, nil
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, fmt.Errorf("%w: %s", errCredentialStoreLocked, lockPath)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func openAdvisoryFileLock(lockPath string) (*os.File, error) {
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open credential lock file: %w", err)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect open credential lock file: %w", err)
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect credential lock file: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !openedInfo.Mode().IsRegular() ||
		!pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		_ = file.Close()
		return nil, errors.New("credential lock path must be a regular file, not a symlink")
	}
	return file, nil
}

func privateFileRevision(path string) (string, error) {
	data, err := readFileLimited(path, maxCredentialFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return credentialFileRevision(nil), nil
		}
		return "", fmt.Errorf("verify credential file revision: %w", err)
	}
	return credentialFileRevision(data), nil
}

func readFileLimited(path string, maximumBytes int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("credential store path must be a regular file")
	}
	if info.Size() > maximumBytes {
		return nil, fmt.Errorf("credential store exceeds %d bytes", maximumBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, errors.New("credential store path must be a regular file")
	}
	if openedInfo.Size() > maximumBytes {
		return nil, fmt.Errorf("credential store exceeds %d bytes", maximumBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximumBytes {
		return nil, fmt.Errorf("credential store exceeds %d bytes", maximumBytes)
	}
	return data, nil
}

func resolveCredentialWritePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("credential store path is empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return path, nil
		}
		return "", fmt.Errorf("inspect credential file: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve credential file symlink: %w", err)
	}
	return resolved, nil
}
