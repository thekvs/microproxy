package main

import (
	"encoding/csv"
	"errors"
	"io"
	"os"
)

type basicAuthData struct {
	user     string
	password string
}

type basicAuth struct {
	Users map[string]string
}

func newBasicAuthFromFile(path string) (*basicAuth, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return newBasicAuth(r)
}

func newBasicAuth(file io.Reader) (*basicAuth, error) {
	csvReader := csv.NewReader(file)
	csvReader.Comma = ':'
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}

	h := &basicAuth{Users: make(map[string]string)}

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

func (h *basicAuth) validate(authData *basicAuthData) bool {
	realPassword, exists := h.Users[authData.user]
	if !exists || realPassword != authData.password {
		return false
	}

	return true
}
