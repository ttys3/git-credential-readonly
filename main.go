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
)

func main() {
	var credFile string
	flag.StringVar(&credFile, "file", defaultCredentialFile, "use given file instead of the default credential file")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("no action specified")
	}
	action := args[0]

	switch action {
	case "get":

		req, err := parseGitCredentials(os.Stdin)
		if err != nil {
			log.Fatalf("get stdin failed, err=%v", err)
		}
		credential := getCredential(req, credFile)
		if credential == nil {
			// credential not found
			os.Exit(1)
		}
		fmt.Printf("username=%s\npassword=%s\n", credential.username, credential.password)
	case "erase", "store":
		// noop
	default:
		log.Fatalf("unsupported action: %s", action)
	}
}

type credential struct {
	protocol string
	username string
	password string
	host     string
	path     string
}

func (c *credential) match(other *credential) bool {
	if c == nil || other == nil {
		return false
	}
	match := c.protocol == other.protocol &&
		c.username == other.username &&
		c.host == other.host
	if other.path == "" {
		return match
	}
	return match && c.path == other.path
}

func parseGitCredentials(r io.Reader) (*credential, error) {
	rd := bufio.NewReader(r)
	c := &credential{}
	for {
		key, err := rd.ReadString('=')
		if err != nil {
			if err == io.EOF {
				if key == "" {
					return c, nil
				}

				return nil, io.ErrUnexpectedEOF
			}

			return nil, err
		}

		key = strings.TrimSuffix(key, "=")
		val, err := rd.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}

			return nil, err
		}

		val = strings.TrimSuffix(val, "\n")
		switch key {
		case "protocol":
			c.protocol = val
		case "host":
			c.host = val
		case "path":
			c.path = val
		case "username":
			c.username = val
		case "password":
			c.password = val
		}
	}
}

func parseCredential(line string) *credential {
	fields := strings.SplitN(line, "://", 2)
	if len(fields) != 2 {
		// malformed line, ignore
		return nil
	}
	proto := fields[0]
	rest := fields[1]

	fields = strings.SplitN(rest, "@", 2)
	if len(fields) != 2 {
		// malformed line, ignore
		return nil
	}

	auth := fields[0]
	credFields := strings.SplitN(auth, ":", 2)
	if len(credFields) != 2 {
		// malformed line, ignore
		return nil
	}
	username := credFields[0]
	password := credFields[1]

	hostAndPath := fields[1]
	hostFields := strings.SplitN(hostAndPath, "/", 2)
	if len(hostFields) != 2 {
		// malformed line, ignore
		return nil
	}
	host := hostFields[0]
	path := hostFields[1]

	return &credential{
		protocol: proto,
		username: username,
		password: password,
		host:     host,
		path:     path,
	}
}

func getCredential(req *credential, credFile string) *credential {
	credPath, err := expandHomeDir(credFile)
	if err != nil {
		log.Fatal(err)
	}

	file, err := os.Open(credPath)
	if err != nil {
		// credential file not found or other error
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		cred := parseCredential(line)
		if cred == nil {
			continue
		}
		if cred.match(req) {
			return cred
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return nil
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
