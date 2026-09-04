package main

import (
	"strings"
	"testing"
)

func TestNormalizeAndValidateCredentialForStorage(t *testing.T) {
	tests := []struct {
		name    string
		value   credential
		wantErr string
	}{
		{
			name: "valid structured credential",
			value: credential{
				protocol: "https",
				host:     "gitlab.example.com:8443",
				path:     "group/subgroup/repository.git",
				username: "developer",
				password: "token",
			},
		},
		{
			name: "invalid protocol",
			value: credential{
				protocol: "https://",
				host:     "example.com",
				username: "user",
				password: "token",
			},
			wantErr: "protocol",
		},
		{
			name: "scheme pasted into host",
			value: credential{
				protocol: "https",
				host:     "https://example.com",
				username: "user",
				password: "token",
			},
			wantErr: "host",
		},
		{
			name: "path pasted into host",
			value: credential{
				protocol: "https",
				host:     "example.com/org/repo",
				username: "user",
				password: "token",
			},
			wantErr: "host",
		},
		{
			name: "invalid port",
			value: credential{
				protocol: "https",
				host:     "example.com:70000",
				username: "user",
				password: "token",
			},
			wantErr: "port",
		},
		{
			name: "empty port",
			value: credential{
				protocol: "https",
				host:     "example.com:",
				username: "user",
				password: "token",
			},
			wantErr: "empty port",
		},
		{
			name: "dot path segment",
			value: credential{
				protocol: "https",
				host:     "example.com",
				path:     "org/../private",
				username: "user",
				password: "token",
			},
			wantErr: "segments",
		},
		{
			name: "encoded dot path segment",
			value: credential{
				protocol: "https",
				host:     "example.com",
				path:     "org/%2e%2e/private",
				username: "user",
				password: "token",
			},
			wantErr: "segments",
		},
		{
			name: "empty path segment",
			value: credential{
				protocol: "https",
				host:     "example.com",
				path:     "org//repo",
				username: "user",
				password: "token",
			},
			wantErr: "empty segments",
		},
		{
			name: "missing username",
			value: credential{
				protocol: "https",
				host:     "example.com",
				password: "token",
			},
			wantErr: "username",
		},
		{
			name: "missing token",
			value: credential{
				protocol: "https",
				host:     "example.com",
				username: "user",
			},
			wantErr: "password or token",
		},
		{
			name: "newline in token",
			value: credential{
				protocol: "https",
				host:     "example.com",
				username: "user",
				password: "token\npassword=leak",
			},
			wantErr: "control characters",
		},
		{
			name: "bidirectional override in username",
			value: credential{
				protocol: "https",
				host:     "example.com",
				username: "user\u202eexample",
				password: "token",
			},
			wantErr: "control characters",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := normalizeCredentialForStorage(test.value)
			err := validateCredentialForStorage(value, true)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validate credential: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestNormalizeCredentialForStorage(t *testing.T) {
	got := normalizeCredentialForStorage(credential{
		protocol: " HTTPS ",
		host:     " GitLab.Example.COM:443 ",
		path:     "/group/subgroup/",
		username: "user",
		password: "token",
	})
	if got.protocol != "HTTPS" || got.host != "GitLab.Example.COM:443" || got.path != "group/subgroup" {
		t.Fatalf("unexpected normalized credential: %+v", got)
	}
}

func TestCredentialIdentityPreservesGitCaseSensitiveMatching(t *testing.T) {
	lower := credential{protocol: "https", host: "example.com", username: "user"}
	mixedCase := credential{protocol: "HTTPS", host: "Example.COM", username: "user"}
	if sameCredentialIdentity(lower, mixedCase) {
		t.Fatal("credential identity collapsed protocol or host case that Git compares exactly")
	}
}

func TestFormatCredentialURLRoundTripsStructuredFields(t *testing.T) {
	want := credential{
		protocol: "HTTPS",
		host:     "GitLab.Example.COM:8443",
		path:     "group/a+b #?/repository.git",
		username: "user+name@example.com",
		password: "tok:en@/%+?",
	}

	encoded, err := formatCredentialURL(want)
	if err != nil {
		t.Fatalf("format credential: %v", err)
	}
	if strings.Contains(encoded, want.password) {
		t.Fatalf("special characters were not encoded in %q", encoded)
	}
	got := parseCredential(encoded)
	if got == nil {
		t.Fatalf("parse generated credential %q", encoded)
	}
	if *got != want {
		t.Fatalf("round-trip credential = %+v, want %+v", *got, want)
	}
}

func TestDisplayCredentialNeverIncludesSecretOrControls(t *testing.T) {
	display := displayCredential(credential{
		protocol: "https",
		host:     "example.com",
		path:     "org/\x1b[31mrepo",
		username: "user",
		password: "top-secret-token",
	})
	if strings.Contains(display, "top-secret-token") {
		t.Fatal("display leaked the credential secret")
	}
	if strings.ContainsRune(display, '\x1b') {
		t.Fatal("display contains a terminal escape character")
	}
}

func TestCredentialInsertionIndexPlacesSpecificScopeFirst(t *testing.T) {
	existing := []credential{
		{protocol: "https", host: "example.com", path: "unrelated", username: "user"},
		{protocol: "https", host: "example.com", path: "group", username: "user"},
	}
	candidate := credential{
		protocol: "https",
		host:     "example.com",
		path:     "group/subgroup/repository.git",
		username: "user",
	}
	if got := credentialInsertionIndex(existing, candidate); got != 1 {
		t.Fatalf("insertion index = %d, want 1", got)
	}

	candidate.path = ""
	if got := credentialInsertionIndex(existing, candidate); got != len(existing) {
		t.Fatalf("broad credential insertion index = %d, want %d", got, len(existing))
	}
}

func TestCredentialInsertionIndexPrioritizesScopeWhenGitOmitsUsername(t *testing.T) {
	broadOnly := []credential{
		{protocol: "https", host: "example.com", path: "group", username: "broad-user"},
	}
	candidate := credential{
		protocol: "https",
		host:     "example.com",
		path:     "group/team/repository.git",
		username: "different-user",
	}
	if got := credentialInsertionIndex(broadOnly, candidate); got != 0 {
		t.Fatalf("insertion index = %d, want 0 before a broader credential", got)
	}

	existing := []credential{
		{protocol: "https", host: "example.com", path: "group/repository.git", username: "existing-user"},
		broadOnly[0],
	}
	candidate.path = "group/repository.git"
	if got := credentialInsertionIndex(existing, candidate); got != 1 {
		t.Fatalf("equal-scope insertion index = %d, want 1 after equal scope and before broad scope", got)
	}
}
