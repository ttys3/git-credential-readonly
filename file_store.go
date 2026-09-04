package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

const maxCredentialFileBytes = 16 * 1024 * 1024

type fileCredentialStore struct {
	path string
}

type credentialFileLine struct {
	value  string
	ending string
}

func newFileCredentialStore(path string) *fileCredentialStore {
	return &fileCredentialStore{path: path}
}

func (s *fileCredentialStore) Backend() credentialBackend {
	return fileBackend
}

func (s *fileCredentialStore) DisplayName() string {
	return "Credential file"
}

func (s *fileCredentialStore) List() ([]credentialRecord, error) {
	lines, revision, err := s.readLines()
	if err != nil {
		return nil, err
	}

	records := make([]credentialRecord, 0, len(lines))
	for position, line := range lines {
		value := parseCredential(line.value)
		if value == nil {
			continue
		}
		value.password = ""
		records = append(records, credentialRecord{
			id:         fileCredentialRecordID(position, line.value),
			backend:    fileBackend,
			credential: *value,
			revision:   revision,
			position:   position,
		})
	}
	return records, nil
}

func (s *fileCredentialStore) Add(value credential) error {
	value = normalizeCredentialForStorage(value)
	if err := validateCredentialForStorage(value, true); err != nil {
		return err
	}
	encoded, err := formatCredentialURL(value)
	if err != nil {
		return err
	}

	lines, revision, err := s.readLines()
	if err != nil {
		return err
	}
	position, err := credentialFileInsertionPosition(lines, value)
	if err != nil {
		return err
	}
	lines = insertCredentialFileLine(lines, position, encoded)
	return s.writeLinesIfUnchanged(lines, revision)
}

func (s *fileCredentialStore) Update(record credentialRecord, value credential) error {
	if record.backend != fileBackend {
		return errors.New("credential does not belong to the file backend")
	}

	lines, revision, err := s.readLines()
	if err != nil {
		return err
	}
	if revision != record.revision || record.position < 0 || record.position >= len(lines) {
		return errCredentialChanged
	}

	existing := parseCredential(lines[record.position].value)
	if existing == nil || fileCredentialRecordID(record.position, lines[record.position].value) != record.id ||
		!sameCredentialMetadata(*existing, record.credential) {
		return errCredentialChanged
	}

	if value.password == "" {
		value.password = existing.password
	}
	value = normalizeCredentialForStorage(value)
	if err := validateCredentialForStorage(value, true); err != nil {
		return err
	}
	encoded, err := formatCredentialURL(value)
	if err != nil {
		return err
	}

	lines = append(lines[:record.position], lines[record.position+1:]...)
	position, err := credentialFileInsertionPosition(lines, value)
	if err != nil {
		return err
	}
	lines = insertCredentialFileLine(lines, position, encoded)
	return s.writeLinesIfUnchanged(lines, revision)
}

func (s *fileCredentialStore) Delete(record credentialRecord) error {
	if record.backend != fileBackend {
		return errors.New("credential does not belong to the file backend")
	}

	lines, revision, err := s.readLines()
	if err != nil {
		return err
	}
	if revision != record.revision || record.position < 0 || record.position >= len(lines) {
		return errCredentialChanged
	}
	existing := parseCredential(lines[record.position].value)
	if existing == nil || fileCredentialRecordID(record.position, lines[record.position].value) != record.id ||
		!sameCredentialMetadata(*existing, record.credential) {
		return errCredentialChanged
	}

	lines = append(lines[:record.position], lines[record.position+1:]...)
	return s.writeLinesIfUnchanged(lines, revision)
}

func (s *fileCredentialStore) Lookup(request *credential) (*credential, error) {
	lines, _, err := s.readLines()
	if err != nil {
		return nil, err
	}
	for position, line := range lines {
		value := parseCredential(line.value)
		if value == nil {
			log.Printf("ignore malformed credential at line %d", position+1)
			continue
		}
		if value.match(request) {
			return value, nil
		}
	}
	return nil, nil
}

func (s *fileCredentialStore) readLines() ([]credentialFileLine, string, error) {
	data, err := readFileLimited(s.path, maxCredentialFileBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, credentialFileRevision(nil), nil
		}
		return nil, "", fmt.Errorf("read credential file: %w", err)
	}
	return splitCredentialFileLines(data), credentialFileRevision(data), nil
}

func (s *fileCredentialStore) writeLinesIfUnchanged(lines []credentialFileLine, revision string) error {
	data := joinCredentialFileLines(lines)
	if len(data) > maxCredentialFileBytes {
		return fmt.Errorf("credential file exceeds %d bytes", maxCredentialFileBytes)
	}
	return writePrivateFileIfUnchanged(s.path, data, revision)
}

func credentialFileRevision(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func fileCredentialRecordID(position int, value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("file:%d:%s", position, hex.EncodeToString(digest[:8]))
}

func credentialFileInsertionPosition(lines []credentialFileLine, candidate credential) (int, error) {
	existing := make([]credential, 0, len(lines))
	positions := make([]int, 0, len(lines))
	for position, line := range lines {
		value := parseCredential(line.value)
		if value == nil {
			continue
		}
		if sameCredentialIdentity(*value, candidate) {
			return 0, errDuplicateCredential
		}
		existing = append(existing, *value)
		positions = append(positions, position)
	}

	index := credentialInsertionIndex(existing, candidate)
	if index < len(positions) {
		return positions[index], nil
	}
	return len(lines), nil
}

func splitCredentialFileLines(data []byte) []credentialFileLine {
	if len(data) == 0 {
		return nil
	}

	remaining := string(data)
	lines := make([]credentialFileLine, 0, strings.Count(remaining, "\n")+1)
	for len(remaining) > 0 {
		newline := strings.IndexByte(remaining, '\n')
		if newline < 0 {
			lines = append(lines, credentialFileLine{value: remaining})
			break
		}

		value := remaining[:newline]
		ending := "\n"
		if strings.HasSuffix(value, "\r") {
			value = strings.TrimSuffix(value, "\r")
			ending = "\r\n"
		}
		lines = append(lines, credentialFileLine{value: value, ending: ending})
		remaining = remaining[newline+1:]
	}
	return lines
}

func joinCredentialFileLines(lines []credentialFileLine) []byte {
	var output strings.Builder
	for _, line := range lines {
		output.WriteString(line.value)
		output.WriteString(line.ending)
	}
	return []byte(output.String())
}

func insertCredentialFileLine(lines []credentialFileLine, position int, value string) []credentialFileLine {
	ending := "\n"
	for _, line := range lines {
		if line.ending != "" {
			ending = line.ending
			break
		}
	}

	if position < 0 {
		position = 0
	}
	if position > len(lines) {
		position = len(lines)
	}
	if position == len(lines) && len(lines) > 0 && lines[len(lines)-1].ending == "" {
		lines[len(lines)-1].ending = ending
	}

	lines = append(lines, credentialFileLine{})
	copy(lines[position+1:], lines[position:])
	lines[position] = credentialFileLine{value: value, ending: ending}
	return lines
}
