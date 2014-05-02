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
	users  map[string]string
	// issued nonce values
	nonces map[string]bool
}

type DigestAuthData struct {
	user     string
	realm    string
	nonce    string
	method   string
	uri      string
	response string
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

	h := &DigestAuth{users: make(map[string]string), nonces: make(map[string]bool)}

	for _, record := range records {
		// each record has to be in form: "user:realm:md5hash"
		if len(record) != 3 {
			return nil, errors.New("invalid htdigest file format")
		}
		key := record[0] + ":" + record[1]
		value := record[2]
		h.users[key] = value
	}

	rand.Seed(time.Now().UnixNano())

	return h, nil
}

func (h *DigestAuth) Validate(data *DigestAuthData) bool {
	lookupKey := data.user + ":" + data.realm
	ha1, exists := h.users[lookupKey]
	if !exists {
		return false
	}

	_, nonceExists := h.nonces[data.nonce]
	if !nonceExists {
		return false
	}

	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(data.method+":"+data.uri)))
	realResponse := fmt.Sprintf("%x", md5.Sum([]byte(ha1+":"+data.nonce+":"+ha2)))

	if data.response == realResponse {
		return true
	}

	return false
}

func (h *DigestAuth) NewNonce() string {
	var nonce string

	for {
		rs := makeRandomString(100)
		nonce = fmt.Sprintf("%x", md5.Sum([]byte(rs)))
		_, exists := h.nonces[nonce]
		if !exists {
			h.addNonce(nonce)
			break
		}
	}

	return nonce
}

func (h *DigestAuth) addNonce(nonce string) {
	h.nonces[nonce] = true
}