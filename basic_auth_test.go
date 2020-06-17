package main

import (
	"bytes"
	"testing"
)

func TestBasicAuthFile(t *testing.T) {
	file := bytes.NewBuffer([]byte("testuser:asdf\n"))
	auth, err := newBasicAuth(file)
	if err != nil {
		t.Errorf("couldn't create basic auth structure")
	}

	if valid := auth.validate(&BasicAuthData{
		user:     "testuser",
		password: "asdf",
	}); !valid {
		t.Errorf("password validation failed")
	}
}
