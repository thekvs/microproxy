package main

import (
	"bytes"
	"testing"
)

func TestBasicAuthFile(t *testing.T) {
	file := bytes.NewBuffer([]byte("testuser:asdf\n"))
	basic_auth, err := NewBasicAuth(file)
	if err != nil {
		t.Errorf("couldn't create basic auth structure")
	}

	if valid := basic_auth.Validate(&BasicAuthData{"testuser", "asdf"}); valid != true {
		t.Errorf("password validation failed")
	}
}
