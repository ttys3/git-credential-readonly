package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeCredentialFile(t *testing.T, credentials ...string) string {
	t.Helper()

	credFile := filepath.Join(t.TempDir(), "credentials")
	contents := strings.Join(credentials, "\n")
	if len(credentials) > 0 {
		contents += "\n"
	}
	if err := os.WriteFile(credFile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return credFile
}

func TestOpenDebugLogRestrictsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses ACLs rather than POSIX permission bits")
	}

	for _, existing := range []bool{false, true} {
		name := "new file"
		if existing {
			name = "existing file"
		}
		t.Run(name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "debug.log")
			if existing {
				if err := os.WriteFile(logPath, []byte("existing log\n"), 0o666); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(logPath, 0o666); err != nil {
					t.Fatal(err)
				}
			}

			logFile, err := openDebugLog(logPath)
			if err != nil {
				t.Fatalf("open debug log: %v", err)
			}
			if err := logFile.Close(); err != nil {
				t.Fatalf("close debug log: %v", err)
			}

			info, err := os.Stat(logPath)
			if err != nil {
				t.Fatalf("stat debug log: %v", err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Errorf("debug log permissions = %04o, want 0600", got)
			}
		})
	}
}

func TestLogCredentialMetadataOmitsPasswordAndEscapesControls(t *testing.T) {
	var logOutput bytes.Buffer
	previousLogOutput := log.Writer()
	previousLogFlags := log.Flags()
	log.SetOutput(&logOutput)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousLogOutput)
		log.SetFlags(previousLogFlags)
	})

	logCredentialMetadata("credential", &credential{
		protocol: "https",
		username: "user",
		password: "secret-token",
		host:     "gitlab.com",
		path:     "group/\rrepository.git",
	})

	got := logOutput.String()
	if strings.Contains(got, "secret-token") {
		t.Fatal("credential password leaked to the log")
	}
	if strings.Contains(got, "\r") {
		t.Fatal("credential path control character was written literally")
	}
	if !strings.Contains(got, `path="group/\rrepository.git"`) {
		t.Errorf("credential path was not safely quoted: %q", got)
	}
}

func TestGetCredential(t *testing.T) {
	credFile := writeCredentialFile(t,
		"https://john:password@github.com/foo/bar",
		"https://octocat:org-password@github.com/acme",
		"https://jane:password@bitbucket.org/foo/bar.git",
	)

	tests := []struct {
		name     string
		request  *credential
		username string
		password string
	}{
		{
			name:     "full repository path",
			request:  &credential{protocol: "https", host: "github.com", path: "foo/bar"},
			username: "john",
			password: "password",
		},
		{
			name:     "owner path",
			request:  &credential{protocol: "https", host: "github.com", path: "acme/widgets.git"},
			username: "octocat",
			password: "org-password",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getCredential(tt.request, credFile)
			if got == nil {
				t.Fatal("expected to find a credential")
			}
			if got.username != tt.username || got.password != tt.password {
				t.Errorf("unexpected credential: %+v", got)
			}
		})
	}

	got := getCredential(
		&credential{username: "john", protocol: "https", host: "bitbucket.org", path: "foo/bar"},
		credFile,
	)
	if got != nil {
		t.Errorf("expected to not find a credential for bitbucket.org/foo/bar")
	}
}

func TestLookupCredentialAutoFallsBackToFile(t *testing.T) {
	credFile := writeCredentialFile(t, "https://user:file-secret@example.com/org/repository.git")
	missingIndex := filepath.Join(t.TempDir(), "missing-keyring-index.json")
	request := &credential{
		protocol: "https",
		host:     "example.com",
		path:     "org/repository.git",
		username: "user",
	}

	got, err := lookupCredential(request, "auto", credFile, missingIndex)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.password != "file-secret" {
		t.Fatalf("auto lookup = %+v, want file fallback", got)
	}
}

func TestLookupCredentialRejectsUnsupportedBackend(t *testing.T) {
	_, err := lookupCredential(&credential{}, "unknown", "unused", "unused")
	if err == nil || !strings.Contains(err.Error(), "unsupported credential backend") {
		t.Fatalf("error = %v, want unsupported backend", err)
	}
}

func TestGetCredentialNestedPathScopes(t *testing.T) {
	credFile := writeCredentialFile(t,
		"https://USERNAME:TOKEN1@gitlab.com/group/subgroup1/project.git",
		"https://USERNAME:TOKEN2@gitlab.com/group/subgroup2/project2.git",
		"https://USERNAME:TOKEN3@gitlab.com/group/subgroup2/",
		"https://USERNAME:TOKEN4@gitlab.com/group/",
	)

	tests := []struct {
		name         string
		path         string
		wantPassword string
	}{
		{
			name:         "exact repository wins when listed first",
			path:         "group/subgroup2/project2.git",
			wantPassword: "TOKEN2",
		},
		{
			name:         "nested subgroup scope",
			path:         "group/subgroup2/another.git",
			wantPassword: "TOKEN3",
		},
		{
			name:         "segment collision falls back to parent scope",
			path:         "group/subgroup20/project.git",
			wantPassword: "TOKEN4",
		},
		{
			name: "similar top-level group does not match",
			path: "group-backup/project.git",
		},
		{
			name:         "missing request path preserves host-only behavior",
			wantPassword: "TOKEN1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getCredential(&credential{
				protocol: "https",
				host:     "gitlab.com",
				path:     tt.path,
				username: "USERNAME",
			}, credFile)
			if tt.wantPassword == "" {
				if got != nil {
					t.Fatalf("unexpected credential: %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected to find a credential")
			}
			if got.password != tt.wantPassword {
				t.Errorf("password = %q, want %q", got.password, tt.wantPassword)
			}
		})
	}
}

func TestGetCredentialKeepsFirstMatchPrecedence(t *testing.T) {
	credFile := writeCredentialFile(t,
		"https://user:group-token@gitlab.com/group",
		"https://user:repository-token@gitlab.com/group/subgroup/project.git",
	)

	got := getCredential(&credential{
		protocol: "https",
		host:     "gitlab.com",
		path:     "group/subgroup/project.git",
		username: "user",
	}, credFile)
	if got == nil {
		t.Fatal("expected to find a credential")
	}
	if got.password != "group-token" {
		t.Errorf("password = %q, want first matching credential", got.password)
	}
}

func TestGetCredentialSkipsMalformedLines(t *testing.T) {
	credFile := writeCredentialFile(t,
		"# comments are not part of the credential-store format",
		"// this is also just a malformed URL",
		"malformed-token-value",
		"https://user:token@gitlab.com/group/repo.git",
	)

	var logOutput bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&logOutput)
	t.Cleanup(func() { log.SetOutput(previousLogOutput) })

	got := getCredential(&credential{
		protocol: "https",
		host:     "gitlab.com",
		path:     "group/repo.git",
		username: "user",
	}, credFile)
	if got == nil || got.password != "token" {
		t.Fatalf("unexpected credential: %+v", got)
	}
	if strings.Contains(logOutput.String(), "malformed-token-value") {
		t.Fatal("malformed credential contents leaked to the log")
	}
}

func TestGetCredentialRejectsEncodedDotSegmentScope(t *testing.T) {
	credFile := writeCredentialFile(t,
		"https://user:token@gitlab.com/group/%2E%2E/",
	)

	got := getCredential(&credential{
		protocol: "https",
		host:     "gitlab.com",
		path:     "group/../private/repo.git",
		username: "user",
	}, credFile)
	if got != nil {
		t.Fatalf("unexpected credential: %+v", got)
	}
}

func TestMatchCredentialPath(t *testing.T) {
	tests := []struct {
		name        string
		configPath  string
		requestPath string
		want        bool
	}{
		{
			name:        "full repository path",
			configPath:  "acme/widgets.git",
			requestPath: "acme/widgets.git",
			want:        true,
		},
		{
			name:        "nested group scope",
			configPath:  "acme/platform",
			requestPath: "acme/platform/widgets.git",
			want:        true,
		},
		{
			name:        "trailing slash",
			configPath:  "acme/",
			requestPath: "acme/widgets.git/",
			want:        true,
		},
		{
			name:        "path segment collision",
			configPath:  "acme/platform",
			requestPath: "acme/platform-tools/widgets.git",
			want:        false,
		},
		{
			name:        "repository name collision",
			configPath:  "acme/widget",
			requestPath: "acme/widgets",
			want:        false,
		},
		{
			name:        "empty config path",
			requestPath: "acme/widgets.git",
			want:        false,
		},
		{
			name:       "empty request path",
			configPath: "acme",
			want:       false,
		},
		{
			name:        "configured path is more specific",
			configPath:  "acme/platform/widgets.git",
			requestPath: "acme/platform",
			want:        false,
		},
		{
			name:        "dot segment cannot inherit scope",
			configPath:  "acme/platform",
			requestPath: "acme/platform/../private/widgets.git",
			want:        false,
		},
		{
			name:        "encoded dot segment cannot inherit scope",
			configPath:  "acme/platform",
			requestPath: "acme/platform/%2e%2E/private:widgets.git",
			want:        false,
		},
		{
			name:        "exact path with dot segment remains exact",
			configPath:  "acme/platform/../private/widgets.git",
			requestPath: "acme/platform/../private/widgets.git",
			want:        true,
		},
		{
			name:        "slash-only config path is not a scope",
			configPath:  "/",
			requestPath: "acme/platform/widgets.git",
			want:        false,
		},
		{
			name:        "encoded root path remains exact",
			configPath:  "/",
			requestPath: "/",
			want:        true,
		},
		{
			name:        "path matching is case sensitive",
			configPath:  "acme/platform",
			requestPath: "Acme/platform/widgets.git",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchCredentialPath(tt.configPath, tt.requestPath); got != tt.want {
				t.Errorf("matchCredentialPath(%q, %q) = %v, want %v",
					tt.configPath, tt.requestPath, got, tt.want)
			}
		})
	}
}

func TestParseCredentialPreservesLiteralPlus(t *testing.T) {
	want := credential{
		protocol: "https",
		username: "user+name",
		password: "token+value",
		host:     "gitlab.com",
		path:     "group/repo+name.git",
	}

	for _, line := range []string{
		"https://user+name:token+value@gitlab.com/group/repo+name.git",
		"https://user%2Bname:token%2Bvalue@gitlab.com/group/repo%2Bname.git",
	} {
		t.Run(line, func(t *testing.T) {
			got := parseCredential(line)
			if got == nil {
				t.Fatal("expected a valid credential")
			}
			if *got != want {
				t.Errorf("credential = %+v, want %+v", *got, want)
			}
		})
	}
}

func TestParseCredentialMatchesGitPercentDecoding(t *testing.T) {
	tests := []struct {
		name string
		line string
		want credential
	}{
		{
			name: "decode once",
			line: "https://user%40example.com:token%3Avalue@gitlab.com/group%2Fsubgroup/repo%252Fname.git",
			want: credential{
				protocol: "https",
				username: "user@example.com",
				password: "token:value",
				host:     "gitlab.com",
				path:     "group/subgroup/repo%2Fname.git",
			},
		},
		{
			name: "preserve malformed and NUL escapes",
			line: "https://user%GG:token%2@gitlab.com/group/%00repo.git",
			want: credential{
				protocol: "https",
				username: "user%GG",
				password: "token%2",
				host:     "gitlab.com",
				path:     "group/%00repo.git",
			},
		},
		{
			name: "trim URL path slashes",
			line: "https://user:token@gitlab.com///group/subgroup///",
			want: credential{
				protocol: "https",
				username: "user",
				password: "token",
				host:     "gitlab.com",
				path:     "group/subgroup",
			},
		},
		{
			name: "preserve possible scheme prefixes",
			line: "https://user:tok%65n:value%41@gitlab%2Eexample:443/group%2Fsub:repo%2Fname.git",
			want: credential{
				protocol: "https",
				username: "user",
				password: "tok%65n:valueA",
				host:     "gitlab%2Eexample:443",
				path:     "group%2Fsub:repo/name.git",
			},
		},
		{
			name: "preserve encoded root path",
			line: "https://user:token@gitlab.com/%2F%2F",
			want: credential{
				protocol: "https",
				username: "user",
				password: "token",
				host:     "gitlab.com",
				path:     "/",
			},
		},
		{
			name: "query marker starts path without a slash",
			line: "https://user:token@gitlab.com?service=git-upload-pack",
			want: credential{
				protocol: "https",
				username: "user",
				password: "token",
				host:     "gitlab.com",
				path:     "?service=git-upload-pack",
			},
		},
		{
			name: "fragment marker starts path without a slash",
			line: "https://user:token@gitlab.com#credential-scope",
			want: credential{
				protocol: "https",
				username: "user",
				password: "token",
				host:     "gitlab.com",
				path:     "#credential-scope",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCredential(tt.line)
			if got == nil {
				t.Fatal("expected a valid credential")
			}
			if *got != tt.want {
				t.Errorf("credential = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestParseCredentialRejectsEncodedControls(t *testing.T) {
	for _, line := range []string{
		"https://user:token%0Asecret@gitlab.com/group/repo.git",
		"https://user%0Dpassword=attacker:token@gitlab.com/group/repo.git",
		"https://user:token%1B%5B31m@gitlab.com/group/repo.git",
	} {
		if got := parseCredential(line); got != nil {
			t.Fatalf("unexpected credential for %q: %+v", line, got)
		}
	}
}

func TestParseCredentialRejectsInvalidStoreURLs(t *testing.T) {
	for _, line := range []string{
		"://user:token@gitlab.com/group/repo.git",
		"https://gitlab.com/group/repo.git",
		"https://user@gitlab.com/group/repo.git",
		"https://gitlab.com?query:user@evil.example/repo.git",
		"https://gitlab.com#fragment:user@evil.example/repo.git",
	} {
		t.Run(line, func(t *testing.T) {
			if got := parseCredential(line); got != nil {
				t.Fatalf("unexpected credential: %+v", got)
			}
		})
	}
}

func TestHasDotPathSegment(t *testing.T) {
	tests := map[string]bool{
		".":                          true,
		"..":                         true,
		"%2e":                        true,
		"%2E":                        true,
		".%2e":                       true,
		"%2e.":                       true,
		"%2e%2E":                     true,
		"group/%2e%2e":               true,
		"group/%2e%2e%2Foutside:foo": true,
		"...":                        false,
		"%252e":                      false,
		"repository":                 false,
	}

	for path, want := range tests {
		t.Run(path, func(t *testing.T) {
			if got := hasDotPathSegment(path); got != want {
				t.Errorf("hasDotPathSegment(%q) = %v, want %v", path, got, want)
			}
		})
	}
}

func TestParseGitCredentialRequest(t *testing.T) {
	want := credential{
		protocol: "https",
		host:     "github.com",
		path:     "acme/widgets.git",
		username: "octocat",
	}

	tests := []struct {
		name  string
		input string
	}{
		{
			name: "EOF terminated",
			input: "protocol=https\n" +
				"host=github.com\n" +
				"path=acme/widgets.git\n" +
				"username=octocat\n",
		},
		{
			name: "blank line terminated",
			input: "protocol=https\n" +
				"host=github.com\n" +
				"path=acme/widgets.git\n" +
				"username=octocat\n\nignored=value\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGitCredentialRequest(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("parse credential request: %v", err)
			}
			if *got != want {
				t.Errorf("unexpected credential request: got %+v, want %+v", *got, want)
			}
		})
	}
}

func TestParseGitCredentialRequestRejectsMalformedAttribute(t *testing.T) {
	_, err := parseGitCredentialRequest(strings.NewReader("protocol=https\nmalformed\n"))
	if err == nil {
		t.Fatal("expected malformed attribute to return an error")
	}
}
