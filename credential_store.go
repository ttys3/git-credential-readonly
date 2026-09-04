package main

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type credentialBackend string

type credentialIdentity struct {
	protocol string
	host     string
	path     string
	username string
}

const (
	fileBackend    credentialBackend = "file"
	keyringBackend credentialBackend = "keyring"

	maxCredentialFieldBytes = 64 * 1024
)

var (
	errCredentialChanged     = errors.New("credential store changed; reload before editing")
	errDuplicateCredential   = errors.New("a credential with the same scope and username already exists")
	errCredentialStoreLocked = errors.New("credential store is locked by another process")
	protocolPattern          = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)
)

// credentialRecord intentionally never carries a password. Backends retrieve
// the existing secret only while applying an edit or satisfying a Git lookup.
type credentialRecord struct {
	id         string
	backend    credentialBackend
	credential credential

	// Stores use revision and position to avoid editing the wrong entry if
	// another process changes the backing metadata while the TUI is open.
	revision string
	position int
}

type managedCredentialStore interface {
	Backend() credentialBackend
	DisplayName() string
	List() ([]credentialRecord, error)
	Add(credential) error
	Update(credentialRecord, credential) error
	Delete(credentialRecord) error
	Lookup(*credential) (*credential, error)
}

func normalizeCredentialForStorage(value credential) credential {
	// Git compares credential protocol and host fields exactly. Trim accidental
	// surrounding whitespace, but preserve case so a TUI-written credential has
	// the same matching semantics as one written by git credential-store.
	value.protocol = strings.TrimSpace(value.protocol)
	value.host = strings.TrimSpace(value.host)

	if value.path != "/" {
		value.path = strings.TrimPrefix(value.path, "/")
		value.path = strings.TrimRight(value.path, "/")
	}

	return value
}

func validateCredentialForStorage(value credential, requirePassword bool) error {
	if err := validateCredentialProtocol(value.protocol); err != nil {
		return err
	}
	if err := validateCredentialHost(value.protocol, value.host); err != nil {
		return err
	}
	if err := validateCredentialPath(value.path); err != nil {
		return err
	}
	if err := validateCredentialUsername(value.username); err != nil {
		return err
	}
	if err := validateCredentialPassword(value.password, requirePassword); err != nil {
		return err
	}

	return nil
}

func validateCredentialProtocol(protocol string) error {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if !protocolPattern.MatchString(protocol) {
		return errors.New("protocol must be a URI scheme such as https")
	}
	return nil
}

func validateCredentialHost(protocol, host string) error {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	host = strings.TrimSpace(host)
	if err := validateCredentialText("host", host, false); err != nil {
		return err
	}
	if strings.ContainsAny(host, "/?#@") {
		return errors.New("host must contain only a hostname and optional port")
	}
	if strings.HasSuffix(host, ":") {
		return errors.New("host must not end with an empty port")
	}

	parsed, err := url.Parse(protocol + "://" + host)
	if err != nil {
		return fmt.Errorf("invalid host or port: %w", err)
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("host must contain only a hostname and optional port")
	}
	if port := parsed.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("port must be between 1 and 65535")
		}
	}
	return nil
}

func validateCredentialPath(path string) error {
	if path != "/" {
		path = strings.TrimPrefix(path, "/")
		path = strings.TrimRight(path, "/")
	}
	if err := validateCredentialText("path", path, true); err != nil {
		return err
	}
	if path == "" || path == "/" {
		return nil
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" {
			return errors.New("path must not contain empty segments")
		}
		decoded := decodePercentEscapes(segment)
		if decoded == "." || decoded == ".." {
			return errors.New("path must not contain . or .. segments")
		}
	}
	return nil
}

func validateCredentialUsername(username string) error {
	return validateCredentialText("username", username, false)
}

func validateCredentialPassword(password string, required bool) error {
	if password == "" && !required {
		return nil
	}
	return validateCredentialText("password or token", password, false)
}

func validateCredentialText(name, value string, allowEmpty bool) error {
	if !allowEmpty && value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > maxCredentialFieldBytes {
		return fmt.Errorf("%s is too long", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%s must not contain control characters", name)
		}
	}
	return nil
}

func formatCredentialURL(value credential) (string, error) {
	value = normalizeCredentialForStorage(value)
	if err := validateCredentialForStorage(value, true); err != nil {
		return "", err
	}

	parsed := url.URL{
		Scheme: value.protocol,
		Host:   value.host,
		User:   url.UserPassword(value.username, value.password),
	}
	if value.path != "" {
		if value.path == "/" {
			parsed.Path = "/"
		} else {
			parsed.Path = "/" + value.path
		}
	}

	encoded := parsed.String()
	if len(encoded)+1 > maxCredentialFieldBytes {
		return "", errors.New("encoded credential is too long")
	}
	return encoded, nil
}

func displayCredential(value credential) string {
	parsed := url.URL{
		Scheme: value.protocol,
		Host:   value.host,
		User:   url.User(value.username),
	}
	if value.path != "" {
		if value.path == "/" {
			parsed.Path = "/"
		} else {
			parsed.Path = "/" + value.path
		}
	}
	return safeTerminalText(parsed.String())
}

func safeTerminalText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '\uFFFD'
		}
		return r
	}, value)
}

func sameCredentialIdentity(left, right credential) bool {
	return credentialIdentityOf(left) == credentialIdentityOf(right)
}

func credentialIdentityOf(value credential) credentialIdentity {
	value = normalizeCredentialForStorage(value)
	return credentialIdentity{
		protocol: value.protocol,
		host:     value.host,
		path:     value.path,
		username: value.username,
	}
}

func sameCredentialMetadata(left, right credential) bool {
	left.password = ""
	right.password = ""
	return sameCredentialIdentity(left, right)
}

func findDuplicateCredential(existing []credential, candidate credential) bool {
	for _, current := range existing {
		if sameCredentialIdentity(current, candidate) {
			return true
		}
	}
	return false
}

// credentialInsertionIndex places a more-specific path before the first
// broader scope that would otherwise shadow it. Unrelated entries retain their
// existing order, and broad credentials are appended after specific ones.
func credentialInsertionIndex(existing []credential, candidate credential) int {
	candidate = normalizeCredentialForStorage(candidate)
	if candidate.path == "" {
		return len(existing)
	}

	for i, current := range existing {
		current = normalizeCredentialForStorage(current)
		if current.protocol != candidate.protocol || current.host != candidate.host ||
			current.path == "" || len(candidate.path) <= len(current.path) {
			continue
		}
		if matchCredentialPath(current.path, candidate.path) {
			return i
		}
	}
	return len(existing)
}
