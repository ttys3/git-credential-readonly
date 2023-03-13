package main

import (
	"bufio"
	"flag"
	"fmt"
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
		if len(args) < 2 {
			log.Fatal("no URL specified")
		}
		credential := getCredential(args[1], credFile)
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
	return c.protocol == other.protocol &&
		c.username == other.username &&
		c.host == other.host &&
		c.path == other.path
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

func getCredential(url, credFile string) *credential {
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
		if cred.protocol == "https" && cred.match(parseCredential(fmt.Sprintf("https://%s", url))) {
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
