package main

import (
	"encoding/csv"
	"errors"
	"io"
	"os"
)

type BasicAuthData struct {
	user     string
	password string
}

type BasicAuth struct {
	Users map[string]string
}

func NewBasicAuthFromFile(path string) (*BasicAuth, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return NewBasicAuth(r)
}

func NewBasicAuth(file io.Reader) (*BasicAuth, error) {
	csv_reader := csv.NewReader(file)
	csv_reader.Comma = ':'
	csv_reader.Comment = '#'
	csv_reader.TrimLeadingSpace = true

	records, err := csv_reader.ReadAll()
	if err != nil {
		return nil, err
	}

	h := &BasicAuth{Users: make(map[string]string)}

	for _, record := range records {
		if len(record) != 2 {
			return nil, errors.New("invalid basic auth file format")
		}
		h.Users[record[0]] = record[1]
	}

	if len(h.Users) == 0 {
		return nil, errors.New("auth file contains no data")
	}

	return h, nil
}

func (h *BasicAuth) validate(authData *BasicAuthData) bool {
	realPassword, exists := h.Users[authData.user]
	if !exists || realPassword != authData.password {
		return false
	}

	return true
}
