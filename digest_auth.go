package main

import (
	"crypto/md5"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"
)

const (
	chars        string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	defaultNonce string = "0e996583b4206e9685e5d69e2af46469"
)

type DigestAuth struct {
	Users map[string]string
}

type DigestAuthData struct {
	User     string
	Realm    string
	Nonce    string
	Method   string
	URI      string
	Response string
}

func makeRandomString(l int) string {
	b := make([]byte, l)
	for i := 0; i < l; i++ {
		b[i] = chars[rand.Intn(len(chars))]
	}

	return string(b)
}

func NewDigestAuthFromFile(path string) (*DigestAuth, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return NewDigestAuth(r)
}

func NewDigestAuth(file io.Reader) (*DigestAuth, error) {
	csv_reader := csv.NewReader(file)
	csv_reader.Comma = ':'
	csv_reader.Comment = '#'
	csv_reader.TrimLeadingSpace = true

	records, err := csv_reader.ReadAll()
	if err != nil {
		return nil, err
	}

	h := &DigestAuth{Users: make(map[string]string)}

	for _, record := range records {
		// each record has to be in form: "user:realm:md5hash"
		if len(record) != 3 {
			return nil, errors.New("invalid htdigest file format")
		}
		key := record[0] + ":" + record[1]
		value := record[2]
		h.Users[key] = value
	}

	rand.Seed(time.Now().UnixNano())

	return h, nil
}

func (h *DigestAuth) Validate(data *DigestAuthData) bool {
	lookupKey := data.User + ":" + data.Realm
	ha1, exists := h.Users[lookupKey]
	if !exists {
		return false
	}

	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(data.Method+":"+data.URI)))
	realResponse := fmt.Sprintf("%x", md5.Sum([]byte(ha1+":"+data.Nonce+":"+ha2)))

	if data.Response == realResponse {
		return true
	}

	return false
}

func (h *DigestAuth) NewNonce() string {
	s := makeRandomString(100)
	nonce := fmt.Sprintf("%x", md5.Sum([]byte(s)))

	return nonce
}
