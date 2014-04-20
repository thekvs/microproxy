package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/elazarl/goproxy"
)

type BasicAuthFunc func(authData *BasicAuthData) *BasicAuthResponse
type DigestAuthFunc func(authData *DigestAuthData, op int) *DigestAuthResponse

var unauthorizedMsg = []byte("407 Proxy Authentication Required")
var proxyAuthorizatonHeader = "Proxy-Authorization"

func BasicUnauthorized(req *http.Request, realm string) *http.Response {
	h := fmt.Sprintf("Basic realm=%s", realm)

	return &http.Response{
		StatusCode:    407,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Proxy-Authenticate": []string{h}},
		Body:          ioutil.NopCloser(bytes.NewBuffer(unauthorizedMsg)),
		ContentLength: int64(len(unauthorizedMsg)),
	}
}

func DigestUnauthorized(req *http.Request, realm string, f DigestAuthFunc) *http.Response {
	r := f(nil, getNonce)
	nonce := r.data
	h := fmt.Sprintf("Digest realm=\"%s\", nonce=\"%s\"", realm, nonce)

	return &http.Response{
		StatusCode:    407,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Proxy-Authenticate": []string{h}},
		Body:          ioutil.NopCloser(bytes.NewBuffer(unauthorizedMsg)),
		ContentLength: int64(len(unauthorizedMsg)),
	}
}

func getDigestAuthData(req *http.Request) *DigestAuthData {
	authheader := strings.SplitN(req.Header.Get(proxyAuthorizatonHeader), " ", 2)
	req.Header.Del(proxyAuthorizatonHeader)

	if len(authheader) != 2 || authheader[0] != "Digest" {
		return nil
	}

	m := make(map[string]string)
	tokens := regexp.MustCompile("\",").Split(authheader[1], -1)

	for _, v := range tokens {
		s := strings.Trim(v, " \r\n")
		kv := strings.SplitN(s, "=", 2)
		if len(kv) != 2 {
			continue
		}
		m[kv[0]] = strings.Trim(kv[1], "\"")
	}

	var data DigestAuthData

	if v, ok := m["username"]; ok {
		data.User = v
	}

	if v, ok := m["realm"]; ok {
		data.Realm = v
	}

	if v, ok := m["nonce"]; ok {
		data.Nonce = v
	}

	if v, ok := m["uri"]; ok {
		data.URI = v
	}

	if v, ok := m["response"]; ok {
		data.Response = v
	}

	data.Method = req.Method

	return &data
}

func getBasicAuthData(req *http.Request) *BasicAuthData {
	authheader := strings.SplitN(req.Header.Get(proxyAuthorizatonHeader), " ", 2)
	req.Header.Del(proxyAuthorizatonHeader)

	if len(authheader) != 2 || authheader[0] != "Basic" {
		return nil
	}

	userpassraw, err := base64.StdEncoding.DecodeString(authheader[1])
	if err != nil {
		return nil
	}

	userpass := strings.SplitN(string(userpassraw), ":", 2)
	if len(userpass) != 2 {
		return nil
	}

	data := BasicAuthData{user: userpass[0], password: userpass[1]}

	return &data
}

func basicAuth(req *http.Request, f BasicAuthFunc) (bool, *BasicAuthData) {
	data := getBasicAuthData(req)
	if data == nil {
		return false, data
	}

	resp := f(data)

	return resp.status, data
}

func digestAuth(req *http.Request, f DigestAuthFunc) (bool, *DigestAuthData) {
	data := getDigestAuthData(req)
	if data == nil {
		return false, data
	}

	authResponse := f(data, validateUser)

	switch authResponse.status {
	case authOk:
		return true, data
	case authFailed:
		return false, data
	default:
		panic("unreachable point")
	}

	return false, data
}

func Basic(realm string, f BasicAuthFunc) goproxy.ReqHandler {
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		status, data := basicAuth(req, f)
		if !status {
			if data != nil {
				ctx.Warnf("failed basic auth. attempt: user=%v, addr=%v", data.user, req.RemoteAddr)
			}
			return nil, BasicUnauthorized(req, realm)
		}
		return req, nil
	})
}

func Digest(realm string, f DigestAuthFunc) goproxy.ReqHandler {
	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		status, data := digestAuth(req, f)
		if !status {
			if data != nil {
				ctx.Warnf("failed digest auth. attempt: user=%v, realm=%v, addr=%v", data.User, data.Realm, req.RemoteAddr)
			}
			return nil, DigestUnauthorized(req, realm, f)
		}
		return req, nil
	})
}

func BasicConnect(realm string, f BasicAuthFunc) goproxy.HttpsHandler {
	return goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		status, data := basicAuth(ctx.Req, f)
		if !status {
			if data != nil {
				ctx.Warnf("failed basic auth. CONNECT method attempt: user=%v, addr=%v", data.user, ctx.Req.RemoteAddr)
			}
			ctx.Resp = BasicUnauthorized(ctx.Req, realm)
			return goproxy.RejectConnect, host
		}
		return goproxy.OkConnect, host
	})
}

func DigestConnect(realm string, f DigestAuthFunc) goproxy.HttpsHandler {
	return goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		status, data := digestAuth(ctx.Req, f)
		if !status {
			if data != nil {
				ctx.Warnf("failed digest auth. CONNECT method attempt: user=%v, realm=%v, addr=%v",
					data.User, data.Realm, ctx.Req.RemoteAddr)
			}
			ctx.Resp = DigestUnauthorized(ctx.Req, realm, f)
			return goproxy.RejectConnect, host
		}
		return goproxy.OkConnect, host
	})
}

func ProxyBasic(proxy *goproxy.ProxyHttpServer, realm string, f BasicAuthFunc) {
	proxy.OnRequest().Do(Basic(realm, f))
	proxy.OnRequest().HandleConnect(BasicConnect(realm, f))
}

func ProxyDigest(proxy *goproxy.ProxyHttpServer, realm string, f DigestAuthFunc) {
	proxy.OnRequest().Do(Digest(realm, f))
	proxy.OnRequest().HandleConnect(DigestConnect(realm, f))
}
