package main

import (
	"bytes"
	"testing"
)

// >>> import hashlib
// >>> ha1 = hashlib.md5("user:remparo:coolpassword").hexdigest()
// >>> ha2 = hashlib.md5("GET:/").hexdigest()
// >>> nonce = "c8f0a8dad4b53c04c1a2c8a05210c7f7"
// >>> response = hashlib.md5(ha1 + ":" + nonce + ":" + ha2).hexdigest()
// >>> response
// 'efa26761794eae48b028c594db95d80a'
// >>> ha1
// '1dccdadf8dfdc350ca2ff04259e6487f'
func TestHtdigest(t *testing.T) {
	file := bytes.NewBuffer([]byte("user:remparo:1dccdadf8dfdc350ca2ff04259e6487f\n"))
	h, err := NewDigestAuth(file)
	if err != nil {
		t.Errorf("couldn't create htdigest file structure")
	}

	data := &DigestAuthData{
		User:     "user",
		Realm:    "remparo",
		Nonce:    "c8f0a8dad4b53c04c1a2c8a05210c7f7",
		Method:   "GET",
		URI:      "/",
		Response: "efa26761794eae48b028c594db95d80a"}
	if valid := h.Validate(data); valid != true {
		t.Errorf("validation failed")
	}
}
