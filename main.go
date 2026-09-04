package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"strings"
)

const (
	defaultCredentialFile = "~/.git-credentials"
	defaultLogFile        = "~/.cache/git-credential-readonly.log"
)

func main() {
	var credFile string
	var logFile string
	var debug bool
	var backend string
	var keyringIndex string

	flag.StringVar(&credFile, "file", defaultCredentialFile, "use given file instead of the default credential file")
	flag.StringVar(&logFile, "log", defaultLogFile, "log file path, used only when debug mode is enabled")
	flag.BoolVar(&debug, "debug", false, "enable debug mode and write log to "+defaultLogFile)
	flag.StringVar(&backend, "backend", string(fileBackend), "credential lookup backend: file, keyring, or auto")
	flag.StringVar(&keyringIndex, "keyring-index", "", "keyring metadata index path (defaults to the user config directory)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if debug {
		var err error
		logFile, err = expandHomeDir(logFile)
		if err != nil {
			log.Fatal(err)
		}
		logOut, err := openDebugLog(logFile)
		if err != nil {
			log.Fatal(err)
		}
		defer logOut.Close()
		log.SetOutput(logOut)
	} else {
		log.SetOutput(io.Discard)
	}

	log.Printf("helper begin |--------------------------------->")
	defer log.Printf("helper end <---------------------------------|\n")

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("no action specified")
	}
	action := args[0]

	switch action {
	case "get":
		log.Printf("begin handle action=%v", action)
		req, err := parseGitCredentialRequest(os.Stdin)
		if err != nil {
			log.Fatalf("get stdin failed, err=%v", err)
		}
		logCredentialMetadata("get request", req)
		credential, err := lookupCredential(req, backend, credFile, keyringIndex)
		if err != nil {
			log.Printf("credential lookup failed: %v", err)
			os.Exit(1)
		}
		if credential == nil {
			// credential not found
			os.Exit(1)
		}
		logCredentialMetadata("get credential success", credential)
		fmt.Printf("username=%s\npassword=%s\n", credential.username, credential.password)
	case "manage", "tui":
		var stores []managedCredentialStore
		var storeWarnings []error

		credPath, err := expandHomeDir(credFile)
		if err != nil {
			storeWarnings = append(storeWarnings, fmt.Errorf("credential file is unavailable: %w", err))
		} else {
			stores = append(stores, newFileCredentialStore(credPath))
		}
		indexPath, err := resolveKeyringIndexPath(keyringIndex)
		if err != nil {
			storeWarnings = append(storeWarnings, fmt.Errorf("system keyring is unavailable: %w", err))
		} else {
			// The manager recommends secure storage, so show it before the
			// compatibility file backend when both are available.
			stores = append([]managedCredentialStore{newKeyringCredentialStore(indexPath)}, stores...)
		}
		if err := runCredentialManager(stores, storeWarnings...); err != nil {
			fmt.Fprintf(os.Stderr, "credential manager failed: %s\n", safeTerminalText(err.Error()))
			os.Exit(1)
		}
	case "erase", "store":
		log.Printf("ignore action=%v", action)
		// noop
	default:
		log.Fatalf("unsupported action=%s", action)
	}
}

func lookupCredential(request *credential, backend, credFile, keyringIndex string) (*credential, error) {
	switch backend {
	case string(fileBackend):
		credPath, err := expandHomeDir(credFile)
		if err != nil {
			return nil, err
		}
		return newFileCredentialStore(credPath).Lookup(request)
	case string(keyringBackend):
		indexPath, err := resolveKeyringIndexPath(keyringIndex)
		if err != nil {
			return nil, err
		}
		return newKeyringCredentialStore(indexPath).Lookup(request)
	case "auto":
		indexPath, err := resolveKeyringIndexPath(keyringIndex)
		var value *credential
		var keyringErr error
		if err == nil {
			value, keyringErr = newKeyringCredentialStore(indexPath).Lookup(request)
		} else {
			keyringErr = err
		}
		if keyringErr == nil && value != nil {
			return value, nil
		}
		if keyringErr != nil {
			log.Printf("keyring lookup failed; falling back to file: %v", keyringErr)
		}
		credPath, err := expandHomeDir(credFile)
		if err != nil {
			return nil, err
		}
		return newFileCredentialStore(credPath).Lookup(request)
	default:
		return nil, fmt.Errorf("unsupported credential backend %q (want file, keyring, or auto)", backend)
	}
}

func resolveKeyringIndexPath(path string) (string, error) {
	if path == "" {
		return defaultKeyringIndexPath()
	}
	return expandHomeDir(path)
}

type credential struct {
	protocol string
	username string
	password string
	host     string
	path     string
}

func openDebugLog(path string) (*os.File, error) {
	logOut, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := logOut.Chmod(0o600); err != nil {
		logOut.Close()
		return nil, err
	}
	return logOut, nil
}

func logCredentialMetadata(event string, credential *credential) {
	log.Printf("%s: protocol=%q,host=%q,path=%q,username=%q",
		event, credential.protocol, credential.host, credential.path, credential.username)
}

func (c *credential) match(req *credential) bool {
	if c == nil || req == nil {
		return false
	}
	match := c.host == req.host

	if req.protocol != "" {
		match = match && c.protocol == req.protocol
	}

	if req.username != "" {
		match = match && c.username == req.username
	}

	if req.path != "" {
		pathMatch := matchCredentialPath(c.path, req.path)
		match = match && pathMatch
		log.Printf("match path: req.path=%q,config.path=%q,result=%v",
			req.path, c.path, match)
	}
	return match
}

func matchCredentialPath(configPath, requestPath string) bool {
	// Keep Git's exact-match behavior, including the encoded-root path "/",
	// before normalizing optional trailing separators for scope matching.
	if configPath != "" && configPath == requestPath {
		return true
	}

	configPath = strings.TrimRight(configPath, "/")
	requestPath = strings.TrimRight(requestPath, "/")

	if configPath == "" || requestPath == "" {
		return false
	}

	if configPath == requestPath {
		return true
	}

	// Scope matching is an extension to credential-store's exact path match.
	// Refuse ambiguous dot segments so a path cannot escape a matched scope.
	if hasDotPathSegment(configPath) || hasDotPathSegment(requestPath) {
		return false
	}

	return len(requestPath) > len(configPath) &&
		strings.HasPrefix(requestPath, configPath) &&
		requestPath[len(configPath)] == '/'
}

func hasDotPathSegment(path string) bool {
	// Git's decoder may preserve escapes before a literal ':', while the URL
	// consumer can still normalize them. Use a fully decoded safety view so an
	// encoded dot or slash cannot hide a path traversal from scope matching.
	for _, segment := range strings.Split(decodePercentEscapes(path), "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func parseGitCredentialRequest(r io.Reader) (*credential, error) {
	scanner := bufio.NewScanner(r)
	req := &credential{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}

		key, val, found := strings.Cut(line, "=")
		if !found {
			return nil, errors.New("malformed credential attribute")
		}

		switch key {
		case "protocol":
			req.protocol = val
		case "host":
			req.host = val
		case "path":
			req.path = val
		case "username":
			req.username = val
		case "password":
			req.password = val
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return req, nil
}

func parseCredential(line string) *credential {
	protoEnd := strings.Index(line, "://")
	if protoEnd <= 0 {
		// malformed line, ignore
		return nil
	}
	proto := line[:protoEnd]
	rest := line[protoEnd+3:]

	hostEnd := strings.IndexAny(rest, "/?#")
	if hostEnd < 0 {
		hostEnd = len(rest)
	}
	at := strings.IndexByte(rest, '@')
	colon := strings.IndexByte(rest, ':')
	if at < 0 || hostEnd <= at || colon < 0 || at <= colon {
		// malformed line, ignore
		return nil
	}
	username := decodeCredentialURLComponent(rest[:colon])
	password := decodeCredentialURLComponent(rest[colon+1 : at])
	host := decodeCredentialURLComponent(rest[at+1 : hostEnd])

	var path string
	if hostEnd < len(rest) {
		rawPath := strings.TrimLeft(rest[hostEnd:], "/")
		path = decodeCredentialURLComponent(rawPath)
		path = trimCredentialURLPath(path)
	}

	for _, field := range []string{proto, username, password, host, path} {
		if validateCredentialText("credential field", field, true) != nil {
			return nil
		}
	}

	return &credential{
		protocol: proto,
		username: username,
		password: password,
		host:     host,
		path:     path,
	}
}

func trimCredentialURLPath(path string) string {
	trimmed := strings.TrimRight(path, "/")
	if path != "" && trimmed == "" {
		return "/"
	}
	return trimmed
}

// decodeCredentialURLComponent follows Git's url_decode_mem: a prefix before
// the first literal ':' is preserved as a possible URL scheme; the remainder
// decodes valid, non-NUL percent escapes exactly once and leaves '+' and
// malformed escapes unchanged.
func decodeCredentialURLComponent(value string) string {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return decodePercentEscapes(value)
	}

	var decoded strings.Builder
	decoded.Grow(len(value))
	decoded.WriteString(value[:colon])
	decoded.WriteString(decodePercentEscapes(value[colon:]))
	return decoded.String()
}

func decodePercentEscapes(value string) string {
	var decoded strings.Builder
	decoded.Grow(len(value))

	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			high, highOK := hexValue(value[i+1])
			low, lowOK := hexValue(value[i+2])
			if highOK && lowOK {
				unescaped := high<<4 | low
				if unescaped != 0 {
					decoded.WriteByte(unescaped)
					i += 2
					continue
				}
			}
		}
		decoded.WriteByte(value[i])
	}

	return decoded.String()
}

func hexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func getCredential(req *credential, credFile string) *credential {
	credPath, err := expandHomeDir(credFile)
	if err != nil {
		log.Printf("expand credential file path: %v", err)
		return nil
	}
	value, err := newFileCredentialStore(credPath).Lookup(req)
	if err != nil {
		log.Printf("read credential file: %v", err)
		return nil
	}
	return value
}

func expandHomeDir(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}

	homedir := os.Getenv("HOME")
	if homedir == "" {
		usr, err := user.Current()
		if err != nil {
			return "", err
		}
		homedir = usr.HomeDir
	}
	return strings.ReplaceAll(path, "~", homedir), nil
}
