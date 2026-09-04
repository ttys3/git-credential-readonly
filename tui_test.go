package main

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

type memoryCredentialStore struct {
	backend credentialBackend
	name    string
	records []credentialRecord

	added   []credential
	updated []credential
	deleted []credentialRecord

	listErr   error
	addErr    error
	updateErr error
	deleteErr error
}

func (s *memoryCredentialStore) Backend() credentialBackend { return s.backend }
func (s *memoryCredentialStore) DisplayName() string        { return s.name }

func (s *memoryCredentialStore) List() ([]credentialRecord, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	records := append([]credentialRecord(nil), s.records...)
	for i := range records {
		records[i].credential.password = ""
	}
	return records, nil
}

func (s *memoryCredentialStore) Add(value credential) error {
	if s.addErr != nil {
		return s.addErr
	}
	s.added = append(s.added, value)
	listed := value
	listed.password = ""
	s.records = append(s.records, credentialRecord{
		id:         "added",
		backend:    s.backend,
		credential: listed,
	})
	return nil
}

func (s *memoryCredentialStore) Update(_ credentialRecord, value credential) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.updated = append(s.updated, value)
	return nil
}

func (s *memoryCredentialStore) Delete(record credentialRecord) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, record)
	for i, existing := range s.records {
		if existing.id == record.id {
			s.records = append(s.records[:i], s.records[i+1:]...)
			break
		}
	}
	return nil
}

func (s *memoryCredentialStore) Lookup(*credential) (*credential, error) {
	return nil, nil
}

func TestCredentialManagerAddUsesStructuredValidatedFields(t *testing.T) {
	store := &memoryCredentialStore{backend: keyringBackend, name: "Test keyring"}
	model, err := newCredentialManagerModel([]managedCredentialStore{store})
	if err != nil {
		t.Fatal(err)
	}
	model.openEditor(credential{protocol: "https"}, true, store)

	want := credential{
		protocol: "https",
		host:     "gitlab.example.com:8443",
		path:     "group/a+b #?/repository.git",
		username: "user+name@example.com",
		password: "tok:en@/%+?",
	}
	setManagerEditorValues(model, want)

	model.prepareSave()
	if model.screen != managerSaveConfirmScreen {
		t.Fatalf("screen = %v, want save confirmation; error = %q", model.screen, model.editorError)
	}
	if strings.Contains(model.View().Content, want.password) {
		t.Fatal("save confirmation exposed the credential secret")
	}
	if !strings.Contains(model.View().Content, "credential.useHttpPath=true") {
		t.Fatal("path-scoped confirmation omitted the required Git configuration guidance")
	}

	model.saveEditor()
	if len(store.added) != 1 {
		t.Fatalf("added credentials = %d, want 1", len(store.added))
	}
	if store.added[0] != want {
		t.Fatalf("added credential = %+v, want %+v", store.added[0], want)
	}
	if model.screen != managerListScreen {
		t.Fatalf("screen = %v, want credential list", model.screen)
	}
	if strings.Contains(model.View().Content, want.password) {
		t.Fatal("credential list exposed the credential secret")
	}
}

func TestCredentialManagerEditorRejectsInvalidFields(t *testing.T) {
	store := &memoryCredentialStore{backend: fileBackend, name: "Credential file"}
	model, err := newCredentialManagerModel([]managedCredentialStore{store})
	if err != nil {
		t.Fatal(err)
	}
	model.openEditor(credential{protocol: "https"}, true, store)
	setManagerEditorValues(model, credential{
		protocol: "https",
		host:     "https://example.com/repository",
		username: "user",
		password: "secret",
	})

	model.prepareSave()
	if model.screen != managerEditorScreen {
		t.Fatalf("screen = %v, want editor", model.screen)
	}
	if !strings.Contains(model.editorError, "host") {
		t.Fatalf("editor error = %q, want host validation error", model.editorError)
	}
	if len(store.added) != 0 {
		t.Fatal("invalid credential was added")
	}

	model.editorInputs[1].SetValue("example.com")
	model.editorInputs[4].SetValue("")
	model.prepareSave()
	if !strings.Contains(model.editorError, "password or token") {
		t.Fatalf("editor error = %q, want required secret error", model.editorError)
	}
}

func TestCredentialManagerRejectsControlCharactersBeforeRendering(t *testing.T) {
	store := &memoryCredentialStore{backend: fileBackend, name: "Credential file"}
	model, err := newCredentialManagerModel([]managedCredentialStore{store})
	if err != nil {
		t.Fatal(err)
	}
	model.openEditor(credential{protocol: "https"}, true, store)
	model.editorField = 1
	model.editorInputs[0].Blur()
	model.editorInputs[1].Focus()

	_, _ = model.updateEditor(tea.PasteMsg{Content: "example.com\x1b[31m"})
	if got := model.editorInputs[1].Value(); strings.ContainsRune(got, '\x1b') {
		t.Fatalf("unsafe input retained a terminal escape: %q", got)
	}
	if err := validateEditorInputSafety(1, "example.com\x1b[31m"); err == nil ||
		!strings.Contains(err.Error(), "control characters") {
		t.Fatalf("safety validation error = %v, want control-character error", err)
	}
	// Lip Gloss itself emits ANSI styling, so check the complete malicious
	// sequence rather than rejecting all escape bytes in the rendered view.
	if strings.Contains(model.View().Content, "example.com\x1b[31m") {
		t.Fatal("unsafe pasted terminal sequence was rendered")
	}
}

func TestCredentialManagerEditLeavesSecretBlankForBackendPreservation(t *testing.T) {
	record := credentialRecord{
		id:      "existing",
		backend: fileBackend,
		credential: credential{
			protocol: "https",
			host:     "example.com",
			path:     "old",
			username: "user",
		},
	}
	store := &memoryCredentialStore{
		backend: fileBackend,
		name:    "Credential file",
		records: []credentialRecord{record},
	}
	model, err := newCredentialManagerModel([]managedCredentialStore{store})
	if err != nil {
		t.Fatal(err)
	}
	model.selectedRecord = record
	model.openEditor(record.credential, false, store)
	model.editorInputs[2].SetValue("new/repository.git")

	model.prepareSave()
	model.saveEditor()
	if len(store.updated) != 1 {
		t.Fatalf("updated credentials = %d, want 1", len(store.updated))
	}
	if store.updated[0].password != "" {
		t.Fatal("editor synthesized or exposed an existing secret")
	}
	if store.updated[0].path != "new/repository.git" {
		t.Fatalf("updated path = %q", store.updated[0].path)
	}
}

func TestCredentialManagerDeleteDefaultsToCancel(t *testing.T) {
	record := credentialRecord{
		id:      "existing",
		backend: keyringBackend,
		credential: credential{
			protocol: "https",
			host:     "example.com",
			username: "user",
		},
	}
	store := &memoryCredentialStore{
		backend: keyringBackend,
		name:    "Test keyring",
		records: []credentialRecord{record},
	}
	model, err := newCredentialManagerModel([]managedCredentialStore{store})
	if err != nil {
		t.Fatal(err)
	}
	model.selectedRecord = record
	model.screen = managerActionScreen
	model.menuIndex = 1

	_, _ = model.updateActionMenu(testManagerEnterKey())
	if model.screen != managerDeleteConfirmScreen || model.menuIndex != 1 {
		t.Fatalf("delete confirmation state = (%v, %d), want Cancel selected", model.screen, model.menuIndex)
	}
	_, _ = model.updateDeleteConfirmation(testManagerEnterKey())
	if len(store.deleted) != 0 {
		t.Fatal("default confirmation deleted the credential")
	}
	if model.screen != managerActionScreen {
		t.Fatalf("screen = %v, want action menu", model.screen)
	}
}

func TestCredentialManagerReloadsAfterConcurrentEdit(t *testing.T) {
	record := credentialRecord{
		id:      "stale",
		backend: fileBackend,
		credential: credential{
			protocol: "https",
			host:     "example.com",
			username: "user",
		},
	}
	store := &memoryCredentialStore{
		backend:   fileBackend,
		name:      "Credential file",
		records:   []credentialRecord{record},
		updateErr: errCredentialChanged,
	}
	model, err := newCredentialManagerModel([]managedCredentialStore{store})
	if err != nil {
		t.Fatal(err)
	}
	model.selectedRecord = record
	model.openEditor(record.credential, false, store)
	model.editorInputs[4].SetValue("replacement-secret")
	model.prepareSave()
	model.saveEditor()

	if model.screen != managerListScreen {
		t.Fatalf("screen = %v, want reloaded credential list", model.screen)
	}
	if len(model.editorInputs) != 0 {
		t.Fatal("editor and replacement secret remained in memory after reload")
	}
}

func TestCredentialManagerKeepsWorkingWhenOneBackendCannotList(t *testing.T) {
	unavailable := &memoryCredentialStore{
		backend: keyringBackend,
		name:    "Test keyring",
		listErr: errors.New("service unavailable\x1b[31m"),
	}
	fileStore := &memoryCredentialStore{backend: fileBackend, name: "Credential file"}
	model, err := newCredentialManagerModel([]managedCredentialStore{unavailable, fileStore})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(model.pendingListStatus, "service unavailable") {
		t.Fatalf("status = %q, want backend warning", model.pendingListStatus)
	}
	if strings.ContainsRune(model.pendingListStatus, '\x1b') {
		t.Fatal("backend error retained a terminal escape")
	}
	if got := len(model.list.Items()); got != 2 {
		t.Fatalf("list items = %d, want Add and Quit", got)
	}
}

func TestCredentialManagerListUsesConventionalQuitKey(t *testing.T) {
	store := &memoryCredentialStore{backend: fileBackend, name: "Credential file"}
	model, err := newCredentialManagerModel([]managedCredentialStore{store})
	if err != nil {
		t.Fatal(err)
	}
	_, cmd := model.updateList(tea.KeyPressMsg(tea.Key{Code: 'q', Text: "q"}))
	if cmd == nil {
		t.Fatal("q did not produce a quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("q command returned %T, want tea.QuitMsg", cmd())
	}
}

func TestCredentialManagerEditorUsesCompactLayoutInSmallTerminal(t *testing.T) {
	store := &memoryCredentialStore{backend: fileBackend, name: "Credential file"}
	model, err := newCredentialManagerModel([]managedCredentialStore{store})
	if err != nil {
		t.Fatal(err)
	}
	model.openEditor(credential{protocol: "https"}, true, store)
	setManagerEditorValues(model, credential{
		protocol: "https",
		host:     "example.com",
		username: "user",
		password: "small-terminal-secret",
	})
	_, _ = model.Update(tea.WindowSizeMsg{Width: 20, Height: 10})

	view := model.View().Content
	if !strings.Contains(view, "[1/5] Protocol") {
		t.Fatalf("compact editor view did not identify the active field: %q", view)
	}
	if strings.Contains(view, "small-terminal-secret") {
		t.Fatal("compact editor exposed the credential secret")
	}
}

func setManagerEditorValues(model *credentialManagerModel, value credential) {
	model.editorInputs[0].SetValue(value.protocol)
	model.editorInputs[1].SetValue(value.host)
	model.editorInputs[2].SetValue(value.path)
	model.editorInputs[3].SetValue(value.username)
	model.editorInputs[4].SetValue(value.password)
}

func testManagerEnterKey() tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter})
}
