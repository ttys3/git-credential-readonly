package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	oskeyring "github.com/zalando/go-keyring"
)

const (
	keyringIndexVersion   = 1
	keyringPayloadVersion = 1
	keyringServiceName    = "git-credential-readonly"
)

var keyringIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type keyringClient interface {
	Set(service, account, secret string) error
	Get(service, account string) (string, error)
	Delete(service, account string) error
}

type systemKeyringClient struct{}

func (systemKeyringClient) Set(service, account, secret string) error {
	return oskeyring.Set(service, account, secret)
}

func (systemKeyringClient) Get(service, account string) (string, error) {
	return oskeyring.Get(service, account)
}

func (systemKeyringClient) Delete(service, account string) error {
	return oskeyring.Delete(service, account)
}

type keyringCredentialStore struct {
	indexPath          string
	service            string
	client             keyringClient
	writeIndexOverride func(keyringIndex, string) error
}

type keyringIndex struct {
	Version        int                      `json:"version"`
	Credentials    []keyringIndexCredential `json:"credentials"`
	PendingDeletes []keyringIndexCredential `json:"pending_deletes,omitempty"`
}

type keyringIndexCredential struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Path     string `json:"path,omitempty"`
	Username string `json:"username"`
}

type keyringCredentialPayload struct {
	Version  int    `json:"version"`
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Path     string `json:"path,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func defaultKeyringIndexPath() (string, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user configuration directory: %w", err)
	}
	return filepath.Join(configDirectory, "git-credential-readonly", "keyring-index.json"), nil
}

func newKeyringCredentialStore(indexPath string) *keyringCredentialStore {
	return &keyringCredentialStore{
		indexPath: indexPath,
		service:   keyringServiceName,
		client:    systemKeyringClient{},
	}
}

func (s *keyringCredentialStore) Backend() credentialBackend {
	return keyringBackend
}

func (s *keyringCredentialStore) DisplayName() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS Keychain"
	case "linux", "freebsd", "openbsd":
		return "Secret Service"
	case "windows":
		return "Windows Credential Manager"
	default:
		return "System keyring"
	}
}

func (s *keyringCredentialStore) List() ([]credentialRecord, error) {
	index, revision, err := s.readIndex()
	if err != nil {
		return nil, err
	}

	records := make([]credentialRecord, 0, len(index.Credentials))
	for position, item := range index.Credentials {
		records = append(records, credentialRecord{
			id:         item.ID,
			backend:    keyringBackend,
			credential: item.credential(),
			revision:   revision,
			position:   position,
		})
	}
	if len(index.PendingDeletes) > 0 {
		return records, fmt.Errorf(
			"%d obsolete keyring item(s) are awaiting secure cleanup; the next keyring change will retry",
			len(index.PendingDeletes),
		)
	}
	return records, nil
}

func (s *keyringCredentialStore) Add(value credential) error {
	value = normalizeCredentialForStorage(value)
	if err := validateCredentialForStorage(value, true); err != nil {
		return err
	}

	lockedPath, index, revision, err := s.lockIndex()
	if err != nil {
		return err
	}
	defer lockedPath.release()
	index, revision, _ = s.cleanupPendingDeletesLocked(index, revision, lockedPath.path)
	if findDuplicateCredential(index.credentials(), value) {
		return errDuplicateCredential
	}

	id, err := newKeyringCredentialID()
	if err != nil {
		return err
	}
	payload, err := marshalKeyringPayload(id, value)
	if err != nil {
		return err
	}
	if err := validateKeyringPayloadSize(payload); err != nil {
		return err
	}
	if err := s.client.Set(s.service, id, payload); err != nil {
		return friendlyKeyringError("store credential", err)
	}

	index.insert(keyringIndexCredentialFrom(id, value))
	newRevision, err := s.persistIndexLocked(index, revision, lockedPath.path)
	if err != nil {
		rollbackErr := s.client.Delete(s.service, id)
		if rollbackErr != nil && !errors.Is(rollbackErr, oskeyring.ErrNotFound) {
			return errors.Join(err, friendlyKeyringError("roll back credential", rollbackErr))
		}
		return err
	}
	_, _, _ = s.cleanupPendingDeletesLocked(index, newRevision, lockedPath.path)
	return nil
}

func (s *keyringCredentialStore) Update(record credentialRecord, value credential) error {
	if record.backend != keyringBackend {
		return errors.New("credential does not belong to the keyring backend")
	}

	lockedPath, index, revision, err := s.lockIndex()
	if err != nil {
		return err
	}
	defer lockedPath.release()
	if revision != record.revision {
		return errCredentialChanged
	}
	position := index.find(record.id)
	if position < 0 || !sameCredentialMetadata(index.Credentials[position].credential(), record.credential) {
		return errCredentialChanged
	}
	index, revision, _ = s.cleanupPendingDeletesLocked(index, revision, lockedPath.path)
	position = index.find(record.id)

	oldPayload, err := s.client.Get(s.service, record.id)
	secretMissing := errors.Is(err, oskeyring.ErrNotFound)
	if err != nil && !secretMissing {
		return friendlyKeyringError("read credential for editing", err)
	}
	if secretMissing {
		if value.password == "" {
			return errors.New("keyring secret is missing; enter a replacement password or token, or delete the stale entry")
		}
	} else {
		oldValue, err := unmarshalKeyringPayload(record.id, oldPayload)
		if err != nil {
			return err
		}
		if !sameCredentialMetadata(oldValue, record.credential) {
			return errors.New("keyring credential metadata does not match its index")
		}
		if value.password == "" {
			value.password = oldValue.password
		}
	}
	value = normalizeCredentialForStorage(value)
	if err := validateCredentialForStorage(value, true); err != nil {
		return err
	}

	remaining := append([]keyringIndexCredential(nil), index.Credentials[:position]...)
	remaining = append(remaining, index.Credentials[position+1:]...)
	remainingIndex := keyringIndex{
		Version:        keyringIndexVersion,
		Credentials:    remaining,
		PendingDeletes: append([]keyringIndexCredential(nil), index.PendingDeletes...),
	}
	if findDuplicateCredential(remainingIndex.credentials(), value) {
		return errDuplicateCredential
	}

	newID, err := newKeyringCredentialID()
	if err != nil {
		return err
	}
	newPayload, err := marshalKeyringPayload(newID, value)
	if err != nil {
		return err
	}
	if err := validateKeyringPayloadSize(newPayload); err != nil {
		return err
	}
	if err := s.client.Set(s.service, newID, newPayload); err != nil {
		return friendlyKeyringError("update credential", err)
	}

	remainingIndex.insert(keyringIndexCredentialFrom(newID, value))
	if !secretMissing {
		remainingIndex.PendingDeletes = append(
			remainingIndex.PendingDeletes,
			index.Credentials[position],
		)
	}
	newRevision, err := s.persistIndexLocked(remainingIndex, revision, lockedPath.path)
	if err != nil {
		rollbackErr := s.client.Delete(s.service, newID)
		if errors.Is(rollbackErr, oskeyring.ErrNotFound) {
			rollbackErr = nil
		}
		if rollbackErr != nil {
			return errors.Join(err, friendlyKeyringError("roll back credential", rollbackErr))
		}
		return err
	}
	_, _, _ = s.cleanupPendingDeletesLocked(remainingIndex, newRevision, lockedPath.path)
	return nil
}

func (s *keyringCredentialStore) Delete(record credentialRecord) error {
	if record.backend != keyringBackend {
		return errors.New("credential does not belong to the keyring backend")
	}

	lockedPath, index, revision, err := s.lockIndex()
	if err != nil {
		return err
	}
	defer lockedPath.release()
	if revision != record.revision {
		return errCredentialChanged
	}
	position := index.find(record.id)
	if position < 0 || !sameCredentialMetadata(index.Credentials[position].credential(), record.credential) {
		return errCredentialChanged
	}
	index, revision, _ = s.cleanupPendingDeletesLocked(index, revision, lockedPath.path)
	position = index.find(record.id)

	oldPayload, err := s.client.Get(s.service, record.id)
	secretMissing := errors.Is(err, oskeyring.ErrNotFound)
	if err != nil && !secretMissing {
		return friendlyKeyringError("read credential before deletion", err)
	}
	if !secretMissing {
		oldValue, err := unmarshalKeyringPayload(record.id, oldPayload)
		if err != nil {
			return err
		}
		if !sameCredentialMetadata(oldValue, record.credential) {
			return errors.New("keyring credential metadata does not match its index")
		}
	}

	removedItem := index.Credentials[position]
	index.Credentials = append(index.Credentials[:position], index.Credentials[position+1:]...)
	if !secretMissing {
		index.PendingDeletes = append(index.PendingDeletes, removedItem)
	}
	newRevision, err := s.persistIndexLocked(index, revision, lockedPath.path)
	if err != nil {
		return err
	}
	_, _, _ = s.cleanupPendingDeletesLocked(index, newRevision, lockedPath.path)
	return nil
}

func (s *keyringCredentialStore) Lookup(request *credential) (*credential, error) {
	if request == nil {
		return nil, nil
	}
	index, _, err := s.readIndex()
	if err != nil {
		return nil, err
	}

	matchingPosition := -1
	matchingPathLength := -1
	for position, item := range index.Credentials {
		metadata := item.credential()
		// A path-scoped secret is not safe to return when Git omitted the path:
		// multiple repositories on the same host would be indistinguishable.
		if request.path == "" && metadata.path != "" {
			continue
		}
		if !metadata.match(request) {
			continue
		}
		if len(metadata.path) > matchingPathLength {
			matchingPosition = position
			matchingPathLength = len(metadata.path)
		}
	}
	if matchingPosition < 0 {
		return nil, nil
	}

	item := index.Credentials[matchingPosition]
	metadata := item.credential()
	secret, err := s.client.Get(s.service, item.ID)
	if err != nil {
		return nil, friendlyKeyringError("read matching credential", err)
	}
	value, err := unmarshalKeyringPayload(item.ID, secret)
	if err != nil {
		return nil, err
	}
	if !sameCredentialMetadata(value, metadata) {
		return nil, errors.New("keyring credential metadata does not match its index")
	}
	if !value.match(request) {
		return nil, errors.New("keyring credential failed verified scope matching")
	}
	return &value, nil
}

func (s *keyringCredentialStore) readIndex() (keyringIndex, string, error) {
	return s.readIndexPath(s.indexPath)
}

func (s *keyringCredentialStore) readIndexPath(path string) (keyringIndex, string, error) {
	data, err := readFileLimited(path, maxCredentialFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			index := keyringIndex{Version: keyringIndexVersion}
			return index, credentialFileRevision(nil), nil
		}
		return keyringIndex{}, "", fmt.Errorf("read keyring index: %w", err)
	}
	if len(data) == 0 {
		return keyringIndex{Version: keyringIndexVersion}, credentialFileRevision(nil), nil
	}
	var index keyringIndex
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return keyringIndex{}, "", fmt.Errorf("decode keyring index: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return keyringIndex{}, "", errors.New("decode keyring index: trailing data")
	}
	if err := validateKeyringIndex(index); err != nil {
		return keyringIndex{}, "", err
	}
	return index, credentialFileRevision(data), nil
}

func (s *keyringCredentialStore) lockIndex() (*lockedPrivatePath, keyringIndex, string, error) {
	lockedPath, err := lockPrivatePath(s.indexPath)
	if err != nil {
		return nil, keyringIndex{}, "", err
	}
	index, revision, err := s.readIndexPath(lockedPath.path)
	if err != nil {
		lockedPath.release()
		return nil, keyringIndex{}, "", err
	}
	return lockedPath, index, revision, nil
}

func (s *keyringCredentialStore) writeIndex(index keyringIndex) error {
	data, err := marshalKeyringIndex(index)
	if err != nil {
		return err
	}
	if err := writePrivateFile(s.indexPath, data); err != nil {
		return fmt.Errorf("write keyring index: %w", err)
	}
	return nil
}

func (s *keyringCredentialStore) persistIndexLocked(
	index keyringIndex,
	expectedRevision, path string,
) (string, error) {
	data, err := marshalKeyringIndex(index)
	if err != nil {
		return "", err
	}
	if s.writeIndexOverride != nil {
		if err := s.writeIndexOverride(index, expectedRevision); err != nil {
			return "", err
		}
		return credentialFileRevision(data), nil
	}
	if err := writePrivateFileIfUnchanged(path, data, expectedRevision); err != nil {
		return "", fmt.Errorf("write keyring index: %w", err)
	}
	return credentialFileRevision(data), nil
}

func marshalKeyringIndex(index keyringIndex) ([]byte, error) {
	if err := validateKeyringIndex(index); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode keyring index: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxCredentialFileBytes {
		return nil, errors.New("keyring index is unexpectedly large")
	}
	return data, nil
}

func (s *keyringCredentialStore) cleanupPendingDeletesLocked(
	index keyringIndex,
	revision, path string,
) (keyringIndex, string, error) {
	if len(index.PendingDeletes) == 0 {
		return index, revision, nil
	}

	remaining := make([]keyringIndexCredential, 0, len(index.PendingDeletes))
	removed := false
	var cleanupErrors []error
	for _, item := range index.PendingDeletes {
		secret, err := s.client.Get(s.service, item.ID)
		if errors.Is(err, oskeyring.ErrNotFound) {
			removed = true
			continue
		}
		if err != nil {
			remaining = append(remaining, item)
			cleanupErrors = append(cleanupErrors, friendlyKeyringError("read obsolete credential", err))
			continue
		}

		value, err := unmarshalKeyringPayload(item.ID, secret)
		if err != nil || !sameCredentialMetadata(value, item.credential()) {
			remaining = append(remaining, item)
			cleanupErrors = append(cleanupErrors, errors.New("obsolete keyring credential metadata does not match its index"))
			continue
		}
		if err := s.client.Delete(s.service, item.ID); err != nil && !errors.Is(err, oskeyring.ErrNotFound) {
			remaining = append(remaining, item)
			cleanupErrors = append(cleanupErrors, friendlyKeyringError("delete obsolete credential", err))
			continue
		}
		removed = true
	}

	index.PendingDeletes = remaining
	if !removed {
		return index, revision, errors.Join(cleanupErrors...)
	}
	newRevision, err := s.persistIndexLocked(index, revision, path)
	if err != nil {
		cleanupErrors = append(cleanupErrors, err)
		return index, revision, errors.Join(cleanupErrors...)
	}
	return index, newRevision, errors.Join(cleanupErrors...)
}

func validateKeyringIndex(index keyringIndex) error {
	if index.Version != keyringIndexVersion {
		return fmt.Errorf("unsupported keyring index version %d", index.Version)
	}
	ids := make(map[string]struct{}, len(index.Credentials))
	identities := make(map[credentialIdentity]struct{}, len(index.Credentials))
	for _, item := range index.Credentials {
		if !keyringIDPattern.MatchString(item.ID) {
			return errors.New("keyring index contains an invalid credential ID")
		}
		if _, exists := ids[item.ID]; exists {
			return errors.New("keyring index contains a duplicate credential ID")
		}
		ids[item.ID] = struct{}{}

		value := item.credential()
		if err := validateCredentialForStorage(value, false); err != nil {
			return fmt.Errorf("keyring index contains invalid credential metadata: %w", err)
		}
		identity := credentialIdentityOf(value)
		if _, exists := identities[identity]; exists {
			return errDuplicateCredential
		}
		identities[identity] = struct{}{}
	}
	for _, item := range index.PendingDeletes {
		if !keyringIDPattern.MatchString(item.ID) {
			return errors.New("keyring index contains an invalid pending-delete ID")
		}
		if _, exists := ids[item.ID]; exists {
			return errors.New("keyring index reuses a credential ID")
		}
		ids[item.ID] = struct{}{}
		if err := validateCredentialForStorage(item.credential(), false); err != nil {
			return fmt.Errorf("keyring index contains invalid pending-delete metadata: %w", err)
		}
	}
	return nil
}

func (index keyringIndex) credentials() []credential {
	values := make([]credential, 0, len(index.Credentials))
	for _, item := range index.Credentials {
		values = append(values, item.credential())
	}
	return values
}

func (index *keyringIndex) insert(item keyringIndexCredential) {
	position := credentialInsertionIndex(index.credentials(), item.credential())
	index.Credentials = append(index.Credentials, keyringIndexCredential{})
	copy(index.Credentials[position+1:], index.Credentials[position:])
	index.Credentials[position] = item
}

func (index keyringIndex) find(id string) int {
	for i, item := range index.Credentials {
		if item.ID == id {
			return i
		}
	}
	return -1
}

func (item keyringIndexCredential) credential() credential {
	return credential{
		protocol: item.Protocol,
		host:     item.Host,
		path:     item.Path,
		username: item.Username,
	}
}

func keyringIndexCredentialFrom(id string, value credential) keyringIndexCredential {
	return keyringIndexCredential{
		ID:       id,
		Protocol: value.protocol,
		Host:     value.host,
		Path:     value.path,
		Username: value.username,
	}
}

func newKeyringCredentialID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate credential ID: %w", err)
	}
	return hex.EncodeToString(id[:]), nil
}

func marshalKeyringPayload(id string, value credential) (string, error) {
	payload := keyringCredentialPayload{
		Version:  keyringPayloadVersion,
		ID:       id,
		Protocol: value.protocol,
		Host:     value.host,
		Path:     value.path,
		Username: value.username,
		Password: value.password,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode keyring credential: %w", err)
	}
	return string(data), nil
}

func validateKeyringPayloadSize(payload string) error {
	// go-keyring documents an approximately 3 KiB combined limit on macOS and
	// a 2560-byte secret limit on Windows. Leave room for the service/account
	// identifiers and platform encoding overhead.
	if (runtime.GOOS == "darwin" || runtime.GOOS == "windows") && len(payload) > 2400 {
		return errors.New("credential is too large for the system keyring")
	}
	return nil
}

func unmarshalKeyringPayload(expectedID, secret string) (credential, error) {
	var payload keyringCredentialPayload
	decoder := json.NewDecoder(strings.NewReader(secret))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return credential{}, fmt.Errorf("decode keyring credential: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return credential{}, errors.New("decode keyring credential: trailing data")
	}
	if payload.Version != keyringPayloadVersion || payload.ID != expectedID {
		return credential{}, errors.New("keyring credential has invalid identity or version")
	}
	value := normalizeCredentialForStorage(credential{
		protocol: payload.Protocol,
		host:     payload.Host,
		path:     payload.Path,
		username: payload.Username,
		password: payload.Password,
	})
	if err := validateCredentialForStorage(value, true); err != nil {
		return credential{}, fmt.Errorf("keyring credential is invalid: %w", err)
	}
	return value, nil
}

func friendlyKeyringError(action string, err error) error {
	if err == nil {
		return nil
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" {
		return fmt.Errorf("%s in Secret Service: %w (ensure a Secret Service provider and D-Bus session are available)", action, err)
	}
	return fmt.Errorf("%s in system keyring: %w", action, err)
}
