package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFileCredentialStoreAddPreservesContentAndOrdersScopes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	broad := "https://user:broad-token@gitlab.example.com/group"
	original := "# preserved, although comments are not valid credential-store entries\r\n" +
		broad + "\r\n" +
		"malformed line that must not be discarded\r\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	store := newFileCredentialStore(path)
	added := credential{
		protocol: "https",
		host:     "gitlab.example.com",
		path:     "group/subgroup/repository.git",
		username: "user",
		password: "specific:@/+ token",
	}
	if err := store.Add(added); err != nil {
		t.Fatalf("add credential: %v", err)
	}

	encoded, err := formatCredentialURL(added)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "# preserved, although comments are not valid credential-store entries\r\n" +
		encoded + "\r\n" +
		broad + "\r\n" +
		"malformed line that must not be discarded\r\n"
	if string(data) != want {
		t.Fatalf("credential file:\n%s\nwant:\n%s", data, want)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("credential file mode = %04o, want 0600", got)
		}
	}

	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}
	for _, record := range records {
		if record.credential.password != "" {
			t.Fatal("listed file credential exposed its password")
		}
	}

	got, err := store.Lookup(&credential{
		protocol: "https",
		host:     "gitlab.example.com",
		path:     "group/subgroup/repository.git",
		username: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.password != added.password {
		t.Fatalf("lookup = %+v, want the specific credential", got)
	}
}

func TestFileCredentialStoreRejectsDuplicate(t *testing.T) {
	path := writeCredentialFile(t, "https://user:old-token@example.com/org/repo.git")
	store := newFileCredentialStore(path)
	err := store.Add(credential{
		protocol: "https",
		host:     "example.com",
		path:     "org/repo.git",
		username: "user",
		password: "new-token",
	})
	if !errors.Is(err, errDuplicateCredential) {
		t.Fatalf("error = %v, want duplicate credential error", err)
	}
}

func TestFileCredentialStoreUpdatePreservesSecretAndReorders(t *testing.T) {
	path := writeCredentialFile(t,
		"https://user:broad-token@example.com/group",
		"https://user:preserved-token@example.com/other",
	)
	store := newFileCredentialStore(path)
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}

	updated := records[1].credential
	updated.path = "group/subgroup/repository.git"
	updated.password = ""
	if err := store.Update(records[1], updated); err != nil {
		t.Fatalf("update credential: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("credential lines = %d, want 2", len(lines))
	}
	first := parseCredential(lines[0])
	if first == nil || first.path != updated.path || first.password != "preserved-token" {
		t.Fatalf("first credential = %+v, want reordered credential with preserved token", first)
	}
}

func TestFileCredentialStoreDetectsConcurrentModification(t *testing.T) {
	path := writeCredentialFile(t, "https://user:token@example.com/org")
	store := newFileCredentialStore(path)
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("https://user:changed@example.com/org\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = store.Update(records[0], credential{
		protocol: "https",
		host:     "example.com",
		path:     "org",
		username: "user",
	})
	if !errors.Is(err, errCredentialChanged) {
		t.Fatalf("error = %v, want concurrent modification error", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(data), "token") && !strings.Contains(string(data), "changed") {
		t.Fatal("concurrent file content was overwritten")
	}
}

func TestFileCredentialStoreDeletePreservesOtherLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	contents := "malformed\nhttps://user:token@example.com/org\nhttps://other:keep@example.net/team\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newFileCredentialStore(path)
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(records[0]); err != nil {
		t.Fatalf("delete credential: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "malformed\nhttps://other:keep@example.net/team\n"
	if string(data) != want {
		t.Fatalf("credential file = %q, want %q", data, want)
	}
}

func TestFileCredentialStoreFollowsExistingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation commonly requires elevated privileges on Windows")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "credentials")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	store := newFileCredentialStore(link)
	if err := store.Add(credential{
		protocol: "https",
		host:     "example.com",
		username: "user",
		password: "token",
	}); err != nil {
		t.Fatalf("add through symlink: %v", err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("credential file symlink was replaced")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "example.com") {
		t.Fatalf("symlink target was not updated: %q", data)
	}
}

func TestFileCredentialStoreOutputIsAcceptedByGitCredentialStore(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git executable is unavailable")
	}
	path := filepath.Join(t.TempDir(), "credentials")
	store := newFileCredentialStore(path)
	want := credential{
		protocol: "HTTPS",
		host:     "GitLab.Example.COM:8443",
		path:     "group/a+b #?/repository.git",
		username: "user+name@example.com",
		password: "tok:en@/%+?",
	}
	if err := store.Add(want); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(gitPath, "credential-store", "--file", path, "get")
	cmd.Stdin = strings.NewReader(
		"protocol=" + want.protocol + "\n" +
			"host=" + want.host + "\n" +
			"path=" + want.path + "\n" +
			"username=" + want.username + "\n\n",
	)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git credential-store get: %v", err)
	}
	got, err := parseGitCredentialRequest(strings.NewReader(string(output)))
	if err != nil {
		t.Fatalf("parse git credential-store output: %v", err)
	}
	if got.username != want.username || got.password != want.password {
		t.Fatalf("git credential-store returned username=%q password length=%d, want username=%q password length=%d",
			got.username, len(got.password), want.username, len(want.password))
	}

	// Our writer must release the same temporary .lock path that Git's built-in
	// credential-store uses, or Git would fail here with a locking error.
	gitWritten := credential{
		protocol: "https",
		host:     "github.example.com",
		path:     "team/repository.git",
		username: "git-user",
		password: "git-written-token",
	}
	cmd = exec.Command(gitPath, "credential-store", "--file", path, "store")
	cmd.Stdin = strings.NewReader(
		"protocol=" + gitWritten.protocol + "\n" +
			"host=" + gitWritten.host + "\n" +
			"path=" + gitWritten.path + "\n" +
			"username=" + gitWritten.username + "\n" +
			"password=" + gitWritten.password + "\n\n",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git credential-store store: %v: %s", err, output)
	}
	assertNoCredentialLockFile(t, path+".lock")

	gotWritten, err := store.Lookup(&gitWritten)
	if err != nil {
		t.Fatalf("lookup Git-written credential: %v", err)
	}
	if gotWritten == nil || gotWritten.password != gitWritten.password {
		t.Fatal("credential written by Git was not readable by the file backend")
	}
}
