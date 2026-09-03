package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetCredential(t *testing.T) {
	credFile := filepath.Join(t.TempDir(), "credentials")
	credentials := []string{
		"https://john:password@github.com/foo/bar",
		"https://octocat:org-password@github.com/acme",
		"https://jane:password@bitbucket.org/foo/bar.git",
	}
	file, err := os.Create(credFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range credentials {
		fmt.Fprintln(file, value)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

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
			name:        "owner path",
			configPath:  "acme",
			requestPath: "acme/widgets.git",
			want:        true,
		},
		{
			name:        "trailing slash",
			configPath:  "acme/",
			requestPath: "acme/widgets.git/",
			want:        true,
		},
		{
			name:        "different repository",
			configPath:  "acme/widgets.git",
			requestPath: "acme/gadgets.git",
			want:        false,
		},
		{
			name:        "different owner",
			configPath:  "acme",
			requestPath: "other/widgets.git",
			want:        false,
		},
		{
			name:        "empty config path",
			requestPath: "acme/widgets.git",
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
