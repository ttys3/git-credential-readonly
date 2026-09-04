package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	oskeyring "github.com/zalando/go-keyring"
)

type fakeKeyringClient struct {
	mu        sync.Mutex
	values    map[string]string
	setErr    error
	getErr    error
	deleteErr error
}

func newFakeKeyringClient() *fakeKeyringClient {
	return &fakeKeyringClient{values: make(map[string]string)}
}

func (f *fakeKeyringClient) Set(service, account, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.values[service+"\x00"+account] = secret
	return nil
}

func (f *fakeKeyringClient) Get(service, account string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return "", f.getErr
	}
	secret, ok := f.values[service+"\x00"+account]
	if !ok {
		return "", oskeyring.ErrNotFound
	}
	return secret, nil
}

func (f *fakeKeyringClient) Delete(service, account string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	key := service + "\x00" + account
	if _, ok := f.values[key]; !ok {
		return oskeyring.ErrNotFound
	}
	delete(f.values, key)
	return nil
}

func newTestKeyringStore(t *testing.T) (*keyringCredentialStore, *fakeKeyringClient) {
	t.Helper()
	client := newFakeKeyringClient()
	store := &keyringCredentialStore{
		indexPath: filepath.Join(t.TempDir(), "keyring-index.json"),
		service:   "test-git-credential-readonly",
		client:    client,
	}
	return store, client
}

func TestKeyringCredentialStoreKeepsSecretsOutOfIndex(t *testing.T) {
	store, client := newTestKeyringStore(t)
	broad := credential{
		protocol: "https",
		host:     "gitlab.example.com",
		path:     "group",
		username: "user",
		password: "broad-secret-token",
	}
	specific := credential{
		protocol: "https",
		host:     "gitlab.example.com",
		path:     "group/subgroup/repository.git",
		username: "user",
		password: "specific-secret-token",
	}
	if err := store.Add(broad); err != nil {
		t.Fatalf("add broad credential: %v", err)
	}
	if err := store.Add(specific); err != nil {
		t.Fatalf("add specific credential: %v", err)
	}

	indexData, err := os.ReadFile(store.indexPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{broad.password, specific.password} {
		if strings.Contains(string(indexData), secret) {
			t.Fatalf("keyring index contains secret %q", secret)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(store.indexPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("keyring index mode = %04o, want 0600", got)
		}
	}

	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}
	if records[0].credential.path != specific.path {
		t.Fatalf("first path = %q, want specific path %q", records[0].credential.path, specific.path)
	}
	for _, record := range records {
		if record.credential.password != "" {
			t.Fatal("listed keyring credential exposed its password")
		}
	}
	if len(client.values) != 2 {
		t.Fatalf("stored keyring item count = %d, want 2", len(client.values))
	}

	got, err := store.Lookup(&credential{
		protocol: "https",
		host:     "gitlab.example.com",
		path:     "group/subgroup/repository.git",
		username: "user",
	})
	if err != nil {
		t.Fatalf("lookup keyring credential: %v", err)
	}
	if got == nil || got.password != specific.password {
		t.Fatalf("lookup = %+v, want specific credential", got)
	}
}

func TestKeyringCredentialStoreRejectsTamperedIndexRouting(t *testing.T) {
	store, _ := newTestKeyringStore(t)
	value := credential{
		protocol: "https",
		host:     "github.com",
		path:     "trusted/repository.git",
		username: "user",
		password: "must-not-leak",
	}
	if err := store.Add(value); err != nil {
		t.Fatal(err)
	}

	index, _, err := store.readIndex()
	if err != nil {
		t.Fatal(err)
	}
	index.Credentials[0].Host = "evil.example.com"
	if err := store.writeIndex(index); err != nil {
		t.Fatal(err)
	}

	got, err := store.Lookup(&credential{
		protocol: "https",
		host:     "evil.example.com",
		path:     "trusted/repository.git",
		username: "user",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want metadata mismatch", err)
	}
	if got != nil {
		t.Fatalf("tampered index returned credential: %+v", got)
	}
}

func TestKeyringCredentialStoreSelectsMostSpecificScopeEvenIfIndexIsReordered(t *testing.T) {
	store, _ := newTestKeyringStore(t)
	broad := credential{
		protocol: "https",
		host:     "gitlab.example.com",
		path:     "group",
		username: "user",
		password: "broad-secret",
	}
	specific := credential{
		protocol: "https",
		host:     "gitlab.example.com",
		path:     "group/subgroup/repository.git",
		username: "user",
		password: "specific-secret",
	}
	if err := store.Add(broad); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(specific); err != nil {
		t.Fatal(err)
	}
	index, _, err := store.readIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Credentials) != 2 {
		t.Fatalf("credential count = %d, want 2", len(index.Credentials))
	}
	index.Credentials[0], index.Credentials[1] = index.Credentials[1], index.Credentials[0]
	if err := store.writeIndex(index); err != nil {
		t.Fatal(err)
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
	if got == nil || got.password != specific.password {
		t.Fatalf("lookup = %+v, want most-specific credential", got)
	}
}

func TestKeyringCredentialStoreRequiresRequestPathForScopedSecrets(t *testing.T) {
	store, _ := newTestKeyringStore(t)
	scoped := credential{
		protocol: "https",
		host:     "example.com",
		path:     "organization/repository.git",
		username: "user",
		password: "scoped-secret",
	}
	if err := store.Add(scoped); err != nil {
		t.Fatal(err)
	}
	request := &credential{protocol: "https", host: "example.com", username: "user"}
	got, err := store.Lookup(request)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("pathless request received scoped credential: %+v", got)
	}

	hostWide := scoped
	hostWide.path = ""
	hostWide.password = "host-wide-secret"
	if err := store.Add(hostWide); err != nil {
		t.Fatal(err)
	}
	got, err = store.Lookup(request)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.password != hostWide.password {
		t.Fatalf("pathless lookup = %+v, want host-wide credential", got)
	}
}

func TestKeyringCredentialStoreUpdatePreservesSecretAndDeleteRemovesIt(t *testing.T) {
	store, client := newTestKeyringStore(t)
	value := credential{
		protocol: "https",
		host:     "example.com",
		path:     "org",
		username: "user",
		password: "preserved-secret",
	}
	if err := store.Add(value); err != nil {
		t.Fatal(err)
	}
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	updated := records[0].credential
	updated.path = "org/team/repository.git"
	updated.password = ""
	if err := store.Update(records[0], updated); err != nil {
		t.Fatalf("update credential: %v", err)
	}
	got, err := store.Lookup(&credential{
		protocol: "https",
		host:     "example.com",
		path:     updated.path,
		username: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.password != value.password {
		t.Fatalf("updated credential = %+v, want preserved password", got)
	}

	records, err = store.List()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(records[0]); err != nil {
		t.Fatalf("delete credential: %v", err)
	}
	if len(client.values) != 0 {
		t.Fatalf("keyring still contains %d item(s)", len(client.values))
	}
	records, err = store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("record count after deletion = %d, want 0", len(records))
	}
}

func TestKeyringCredentialStoreCanRemoveAndRepairMissingSecret(t *testing.T) {
	store, client := newTestKeyringStore(t)
	value := credential{
		protocol: "https",
		host:     "example.com",
		path:     "org",
		username: "user",
		password: "original-secret",
	}
	if err := store.Add(value); err != nil {
		t.Fatal(err)
	}
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	delete(client.values, store.service+"\x00"+records[0].id)

	err = store.Update(records[0], records[0].credential)
	if err == nil || !strings.Contains(err.Error(), "secret is missing") {
		t.Fatalf("error = %v, want missing secret guidance", err)
	}

	replacement := records[0].credential
	replacement.password = "replacement-secret"
	if err := store.Update(records[0], replacement); err != nil {
		t.Fatalf("repair missing keyring secret: %v", err)
	}
	got, err := store.Lookup(&credential{
		protocol: "https",
		host:     "example.com",
		path:     "org",
		username: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.password != replacement.password {
		t.Fatalf("repaired credential = %+v, want replacement secret", got)
	}

	records, err = store.List()
	if err != nil {
		t.Fatal(err)
	}
	delete(client.values, store.service+"\x00"+records[0].id)
	if err := store.Delete(records[0]); err != nil {
		t.Fatalf("remove stale keyring index entry: %v", err)
	}
	records, err = store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("stale keyring records = %d, want 0", len(records))
	}
}

func TestKeyringCredentialStoreDetectsConcurrentIndexChange(t *testing.T) {
	store, _ := newTestKeyringStore(t)
	first := credential{protocol: "https", host: "one.example.com", username: "user", password: "one"}
	second := credential{protocol: "https", host: "two.example.com", username: "user", password: "two"}
	if err := store.Add(first); err != nil {
		t.Fatal(err)
	}
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(second); err != nil {
		t.Fatal(err)
	}

	err = store.Update(records[0], records[0].credential)
	if !errors.Is(err, errCredentialChanged) {
		t.Fatalf("error = %v, want concurrent index change error", err)
	}
}

func TestKeyringCredentialStoreSerializesConcurrentUpdates(t *testing.T) {
	store, client := newTestKeyringStore(t)
	original := credential{
		protocol: "https",
		host:     "example.com",
		path:     "original",
		username: "user",
		password: "preserved-secret",
	}
	if err := store.Add(original); err != nil {
		t.Fatal(err)
	}
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	record := records[0]

	start := make(chan struct{})
	results := make(chan error, 2)
	var updates sync.WaitGroup
	for _, path := range []string{"first/repository.git", "second/repository.git"} {
		path := path
		updates.Add(1)
		go func() {
			defer updates.Done()
			<-start
			value := record.credential
			value.path = path
			results <- store.Update(record, value)
		}()
	}
	close(start)
	updates.Wait()
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
			t.Fatalf("unexpected update error: %v", err)
		}
	}
	if successes != 1 || changed != 1 {
		t.Fatalf("successes = %d, changed = %d; want 1 and 1", successes, changed)
	}

	records, err = store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	got, err := store.Lookup(&records[0].credential)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.password != original.password {
		t.Fatalf("winning credential = %+v, want preserved secret", got)
	}
	client.mu.Lock()
	keyringItems := len(client.values)
	client.mu.Unlock()
	if keyringItems != 1 {
		t.Fatalf("keyring item count = %d, want 1", keyringItems)
	}
}

func TestKeyringCredentialStoreRollsBackSecretWhenIndexWriteFails(t *testing.T) {
	store, client := newTestKeyringStore(t)
	store.writeIndexOverride = func(keyringIndex, string) error {
		return errors.New("simulated index failure")
	}
	err := store.Add(credential{
		protocol: "https",
		host:     "example.com",
		username: "user",
		password: "secret",
	})
	if err == nil || !strings.Contains(err.Error(), "simulated index failure") {
		t.Fatalf("error = %v, want simulated index failure", err)
	}
	if len(client.values) != 0 {
		t.Fatalf("keyring contains %d orphaned item(s) after rollback", len(client.values))
	}
}

func TestKeyringCredentialStoreUpdateFailureLeavesOriginalUsable(t *testing.T) {
	store, client := newTestKeyringStore(t)
	original := credential{
		protocol: "https",
		host:     "example.com",
		path:     "original/repository.git",
		username: "user",
		password: "original-secret",
	}
	if err := store.Add(original); err != nil {
		t.Fatal(err)
	}
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	store.writeIndexOverride = func(keyringIndex, string) error {
		return errors.New("simulated index failure")
	}
	updated := records[0].credential
	updated.path = "updated/repository.git"
	updated.password = "replacement-secret"
	if err := store.Update(records[0], updated); err == nil ||
		!strings.Contains(err.Error(), "simulated index failure") {
		t.Fatalf("update error = %v, want index failure", err)
	}
	store.writeIndexOverride = nil

	got, err := store.Lookup(&credential{
		protocol: original.protocol,
		host:     original.host,
		path:     original.path,
		username: original.username,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.password != original.password {
		t.Fatalf("original credential = %+v, want usable original", got)
	}
	client.mu.Lock()
	keyringItems := len(client.values)
	client.mu.Unlock()
	if keyringItems != 1 {
		t.Fatalf("keyring item count = %d, want only original", keyringItems)
	}
}

func TestKeyringCredentialStoreTracksAndRetriesFailedCleanup(t *testing.T) {
	store, client := newTestKeyringStore(t)
	original := credential{
		protocol: "https",
		host:     "example.com",
		path:     "original/repository.git",
		username: "user",
		password: "original-secret",
	}
	if err := store.Add(original); err != nil {
		t.Fatal(err)
	}
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	client.deleteErr = errors.New("simulated keyring cleanup failure")
	updated := records[0].credential
	updated.path = "updated/repository.git"
	if err := store.Update(records[0], updated); err != nil {
		t.Fatalf("commit update with deferred cleanup: %v", err)
	}

	records, err = store.List()
	if err == nil || !strings.Contains(err.Error(), "awaiting secure cleanup") {
		t.Fatalf("list error = %v, want cleanup warning", err)
	}
	if len(records) != 1 || records[0].credential.path != updated.path {
		t.Fatalf("active records = %+v, want updated credential", records)
	}
	got, lookupErr := store.Lookup(&records[0].credential)
	if lookupErr != nil {
		t.Fatal(lookupErr)
	}
	if got == nil || got.password != original.password {
		t.Fatalf("updated credential = %+v, want preserved secret", got)
	}
	client.mu.Lock()
	itemsBeforeRetry := len(client.values)
	client.deleteErr = nil
	client.mu.Unlock()
	if itemsBeforeRetry != 2 {
		t.Fatalf("items before retry = %d, want active and obsolete items", itemsBeforeRetry)
	}

	if err := store.Add(credential{
		protocol: "https",
		host:     "another.example.com",
		username: "other",
		password: "other-secret",
	}); err != nil {
		t.Fatalf("add credential while retrying cleanup: %v", err)
	}
	index, _, err := store.readIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.PendingDeletes) != 0 {
		t.Fatalf("pending deletes = %d, want 0 after retry", len(index.PendingDeletes))
	}
	client.mu.Lock()
	itemsAfterRetry := len(client.values)
	client.mu.Unlock()
	if itemsAfterRetry != 2 {
		t.Fatalf("items after retry = %d, want two active credentials", itemsAfterRetry)
	}
}

func TestKeyringCredentialStoreDoesNotDeleteTamperedPendingItem(t *testing.T) {
	store, client := newTestKeyringStore(t)
	original := credential{
		protocol: "https",
		host:     "example.com",
		path:     "original",
		username: "user",
		password: "original-secret",
	}
	if err := store.Add(original); err != nil {
		t.Fatal(err)
	}
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	client.deleteErr = errors.New("defer cleanup")
	updated := records[0].credential
	updated.path = "updated"
	if err := store.Update(records[0], updated); err != nil {
		t.Fatal(err)
	}
	client.deleteErr = nil

	index, _, err := store.readIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.PendingDeletes) != 1 {
		t.Fatalf("pending deletes = %d, want 1", len(index.PendingDeletes))
	}
	pendingID := index.PendingDeletes[0].ID
	index.PendingDeletes[0].Host = "tampered.example.com"
	if err := store.writeIndex(index); err != nil {
		t.Fatal(err)
	}

	if err := store.Add(credential{
		protocol: "https",
		host:     "another.example.com",
		username: "other",
		password: "other-secret",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(store.service, pendingID); err != nil {
		t.Fatalf("tampered pending item was removed: %v", err)
	}
	index, _, err = store.readIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.PendingDeletes) != 1 {
		t.Fatalf("pending deletes = %d, want tampered item retained", len(index.PendingDeletes))
	}
}

func TestKeyringCredentialPayloadRejectsTrailingData(t *testing.T) {
	id := strings.Repeat("a", 32)
	payload, err := marshalKeyringPayload(id, credential{
		protocol: "https",
		host:     "example.com",
		username: "user",
		password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unmarshalKeyringPayload(id, payload+` {}`); err == nil {
		t.Fatal("trailing JSON data was accepted")
	}
}
