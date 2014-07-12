package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

type myHandler struct {
	headers map[string]string
}

func (h *myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	found := false

	for h, v := range h.headers {
		found = (r.Header.Get(h) == v)
		if !found {
			break
		}
	}

	if found {
		fmt.Fprint(w, "OK")
	} else {
		fmt.Fprintf(w, "FAIL. Headers: %v", r.Header)
	}
}

func TestCustomHeaders(t *testing.T) {
	expectedResponse := "OK"
	expectedHeaders := map[string]string{
		"X-Custom-Header-1": "Value-1",
		"X-Custom-Header-2": "Value-2",
	}

	handler := &myHandler{headers: expectedHeaders}

	background := httptest.NewServer(handler)
	defer background.Close()

	client, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := fmt.Sprint(`{"add_headers": {"X-Custom-Header-1": "Value-1", "X-Custom-Header-2": "Value-2"}}`)
	conf := newConfiguration(bytes.NewBuffer([]byte(s)))
	setAddCustomHeadersHandler(conf, proxy)

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Error("Expected 200 status code, got", resp.Status)
	}

	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	actualResponse := string(msg)
	if actualResponse != expectedResponse {
		t.Errorf("Expected '%s', actual '%s'", expectedResponse, actualResponse)
	}
}

func TestViaHeaders(t *testing.T) {
	expectedResponse := "OK"
	expectedHeaders := map[string]string{
		"Via": "1.1 octopus",
	}

	handler := &myHandler{headers: expectedHeaders}

	background := httptest.NewServer(handler)
	defer background.Close()

	client, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := fmt.Sprint(`{"via_header": "on", "via_proxy_name": "octopus"}`)
	conf := newConfiguration(bytes.NewBuffer([]byte(s)))
	setViaHeaderHandler(conf, proxy)

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Error("Expected 200 status code, got", resp.Status)
	}

	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	actualResponse := string(msg)
	if actualResponse != expectedResponse {
		t.Errorf("Expected '%s', actual '%s'", expectedResponse, actualResponse)
	}
}
