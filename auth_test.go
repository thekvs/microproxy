package main

import (
	"github.com/elazarl/goproxy"

	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// >>> import hashlib
// >>> ha1 = hashlib.md5("user:my_realm:open sesame").hexdigest()
// >>> ha1
// 'e0d80a524f34d30b658136e2e89c1677'
const (
	user     = "user"
	password = "open sesame"
	realm    = "my_realm"
	ha1      = "e0d80a524f34d30b658136e2e89c1677"
	nc       = "00000001"
	cnonce   = "7e1d7e39d76092ea"
	uri      = "/"
	method   = "GET"
	qop      = "auth"
)

type ConstantHanlder string

func (h ConstantHanlder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, string(h))
}

func oneShotProxy() (client *http.Client, proxy *goproxy.ProxyHttpServer, s *httptest.Server) {
	proxy = goproxy.NewProxyHttpServer()
	s = httptest.NewServer(proxy)

	proxyURL, _ := url.Parse(s.URL)
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{Transport: tr}
	return
}

func times(n int, s string) string {
	r := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		r = append(r, s...)
	}
	return string(r)
}

func TestBasicConnectAuthWithCurl(t *testing.T) {
	expected := ":c>"

	background := httptest.NewTLSServer(ConstantHanlder(expected))
	defer background.Close()

	_, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := user + ":" + password + "\n"
	file := bytes.NewBuffer([]byte(s))
	auth, err := newBasicAuth(file)
	if err != nil {
		t.Fatalf("couldn't create digest auth structure: %v", err)
	}
	setProxyBasicAuth(proxy, realm, makeBasicAuthValidator(auth), nil)

	authString := user + ":" + password
	cmd := exec.Command("curl",
		"--silent",
		"--show-error",
		"--insecure",
		"--proxy", proxyserver.URL,
		"--proxy-user", authString,
		"--proxytunnel",
		"--url", background.URL+"/[1-3]",
	)

	out, err := cmd.CombinedOutput() // if curl got error, it'll show up in stderr
	if err != nil {
		t.Fatal(err, string(out))
	}

	finalexpected := times(3, expected)
	if string(out) != finalexpected {
		t.Error("Expected", finalexpected, "got", string(out))
	}
}

func TestBasicAuthWithCurl(t *testing.T) {
	expected := ":c>"

	background := httptest.NewServer(ConstantHanlder(expected))
	defer background.Close()

	_, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := user + ":" + password + "\n"
	file := bytes.NewBuffer([]byte(s))
	auth, err := newBasicAuth(file)
	if err != nil {
		t.Fatalf("couldn't create digest auth structure: %v", err)
	}
	setProxyBasicAuth(proxy, realm, makeBasicAuthValidator(auth), nil)

	authString := user + ":" + password
	cmd := exec.Command("curl",
		"--silent",
		"--show-error",
		"--proxy", proxyserver.URL,
		"--proxy-user", authString,
		"--url", background.URL+"/[1-3]",
	)

	out, err := cmd.CombinedOutput() // if curl got error, it'll show up in stderr
	if err != nil {
		t.Fatal(err, string(out))
	}

	finalexpected := times(3, expected)
	if string(out) != finalexpected {
		t.Error("Expected", finalexpected, "got", string(out))
	}
}

func TestBasicAuth(t *testing.T) {
	expected := "hello"

	background := httptest.NewServer(ConstantHanlder(expected))
	defer background.Close()

	client, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := user + ":" + password + "\n"
	file := bytes.NewBuffer([]byte(s))
	auth, err := newBasicAuth(file)
	if err != nil {
		t.Fatalf("couldn't create digest auth structure: %v", err)
	}
	setProxyBasicAuth(proxy, realm, makeBasicAuthValidator(auth), nil)

	// without auth
	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}
	expectedProxyAuthenticate := fmt.Sprintf("Basic realm=\"%s\"", realm)
	if resp.Header.Get("Proxy-Authenticate") != expectedProxyAuthenticate {
		t.Error("Expected Proxy-Authenticate header got", resp.Header.Get("Proxy-Authenticate"))
	}
	if resp.StatusCode != 407 {
		t.Error("Expected status 407 Proxy Authentication Required, got", resp.Status)
	}

	// with auth
	req, err := http.NewRequest("GET", background.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	authString := user + ":" + password
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(authString))
	req.Header.Set("Proxy-Authorization", header)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Error("Expected status 200 OK, got", resp.Status)
	}
	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "hello" {
		t.Errorf("Expected '%s', actual '%s'", expected, string(msg))
	}
}

func TestDigestAuth(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(ConstantHanlder(expected))
	defer background.Close()

	client, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := user + ":" + realm + ":" + ha1 + "\n"
	file := bytes.NewBuffer([]byte(s))
	auth, err := newDigestAuth(file)
	if err != nil {
		t.Fatalf("couldn't create digest auth structure: %v", err)
	}
	setProxyDigestAuth(proxy, realm, makeDigestAuthValidator(auth), nil)

	// without auth
	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	header := resp.Header.Get("Proxy-Authenticate")
	if len(header) == 0 {
		t.Error("Couldn't get expected Proxy-Authenticate header")
	}

	splitted := strings.SplitN(header, " ", 2)
	if splitted[0] != "Digest" {
		t.Error("Expected Digest Proxy-Authenticate header got", header)
	}
	if resp.StatusCode != 407 {
		t.Error("Expected status 407 Proxy Authentication Required, got", resp.Status)
	}

	nonceRegexp := regexp.MustCompile("nonce=\"(.*?)\"")
	nonce := nonceRegexp.FindAllStringSubmatch(splitted[1], -1)[0][1]

	s = method + ":" + uri
	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(s)))
	s = ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2
	response := fmt.Sprintf("%x", md5.Sum([]byte(s)))

	proxyAuthorizationHeader := fmt.Sprintf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", qop=%s, nc=%s, cnonce=\"%s\"",
		user, realm, nonce, uri, response, qop, nc, cnonce)

	// with auth
	req, err := http.NewRequest("GET", background.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", proxyAuthorizationHeader)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Error("Expected status 200 OK, got", resp.Status)
	}

	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != expected {
		t.Errorf("Expected '%s', actual '%s'", expected, string(msg))
	}
}

func TestDigestAuthWithPython(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(ConstantHanlder(expected))
	defer background.Close()

	_, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := user + ":" + realm + ":" + ha1 + "\n"
	file := bytes.NewBuffer([]byte(s))
	auth, err := newDigestAuth(file)
	if err != nil {
		t.Fatalf("couldn't create digest auth structure: %v", err)
	}
	setProxyDigestAuth(proxy, realm, makeDigestAuthValidator(auth), nil)

	cmd := exec.Command("python",
		"proxy-digest-auth-test.py",
		"--proxy", proxyserver.URL,
		"--user", user,
		"--password", password,
		"--url", background.URL,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}

	// python adds '\n' so we need to remove it
	result := strings.Trim(string(out), "\r\n")
	if result != expected {
		t.Error("Expected", expected, "got", result)
	}
}

func TestDigestAuthWithCurl(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(ConstantHanlder(expected))
	defer background.Close()

	_, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := user + ":" + realm + ":" + ha1 + "\n"
	file := bytes.NewBuffer([]byte(s))
	auth, err := newDigestAuth(file)
	if err != nil {
		t.Fatalf("couldn't create digest auth structure: %v", err)
	}
	setProxyDigestAuth(proxy, realm, makeDigestAuthValidator(auth), nil)

	authString := user + ":" + password
	cmd := exec.Command("curl",
		"--silent",
		"--show-error",
		"--proxy-digest",
		"--proxy", proxyserver.URL,
		"--proxy-user", authString,
		"--url", background.URL,
	)

	out, err := cmd.CombinedOutput() // if curl got error, it'll show up in stderr
	if err != nil {
		t.Fatal(err, string(out))
	}

	result := string(out)

	if result != expected {
		t.Error("Expected", expected, "got", result)
	}
}

func TestIPBasedAccessDenied(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(ConstantHanlder(expected))
	defer background.Close()

	client, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := "{\"allowed_networks\": [\"172.16.11.0/24\"]}\n"
	conf := newConfiguration(bytes.NewBuffer([]byte(s)))
	setAllowedNetworksHandler(conf, proxy)

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 403 {
		t.Error("Expected 403 status code, got", resp.Status)
	}
}

func TestIPBasedAccessAllowed(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewServer(ConstantHanlder(expected))
	defer background.Close()

	client, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := "{\"allowed_networks\": [\"127.0.0.1/32\"]}\n"
	conf := newConfiguration(bytes.NewBuffer([]byte(s)))
	setAllowedNetworksHandler(conf, proxy)

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

	actual := string(msg)
	if actual != expected {
		t.Errorf("Expected '%s', actual '%s'", expected, actual)
	}
}

func TestHTTPSConnectDenied(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewTLSServer(ConstantHanlder(expected))
	defer background.Close()

	client, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	// test server'll bind to the port different from 443
	s := fmt.Sprintf("{\"allowed_connect_ports\": [\"%d\"]}\n", 443)
	conf := newConfiguration(bytes.NewBuffer([]byte(s)))
	setAllowedConnectPortsHandler(conf, proxy)

	_, err := client.Get(background.URL)
	if err == nil {
		t.Fatal(err)
	}
}

func TestHTTPSConnectAllowed(t *testing.T) {
	expected := "Hello, World!"

	background := httptest.NewTLSServer(ConstantHanlder(expected))
	defer background.Close()

	parsedURL, err := url.Parse(background.URL)
	port, err := strconv.ParseUint(strings.Split(parsedURL.Host, ":")[1], 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	client, proxy, proxyserver := oneShotProxy()
	defer proxyserver.Close()

	s := fmt.Sprintf("{\"allowed_connect_ports\": [%d]}\n", port)
	conf := newConfiguration(bytes.NewBuffer([]byte(s)))
	setAllowedConnectPortsHandler(conf, proxy)

	resp, err := client.Get(background.URL)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 200 {
		t.Error("Expected 200 status code, got", resp.Status)
	}
}
