package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestGetCredential(t *testing.T) {
	// create a temporary credential file
	credFile, err := ioutil.TempFile("", "test-cred")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(credFile.Name())

	// write some credentials to the file
	creds := []string{
		"https://john:password@github.com/foo/bar",
		"https://jane:password@bitbucket.org/foo/bar.git",
	}
	for _, cred := range creds {
		fmt.Fprintln(credFile, cred)
	}

	// test getting a credential that exists in the file
	c := getCredential(&credential{username: "john", protocol: "https", host: "github.com", path: "foo/bar"}, credFile.Name())
	if c == nil {
		t.Errorf("expected to find a credential for github.com/foo/bar")
	}
	if c.username != "john" || c.password != "password" {
		t.Errorf("unexpected credential found: %+v", c)
	}

	// test getting a credential that does not exist in the file
	c = getCredential(&credential{username: "john", protocol: "https", host: "bitbucket.org", path: "foo/bar"}, credFile.Name())
	if c != nil {
		t.Errorf("expected to not find a credential for bitbucket.org/foo/bar")
	}
}
