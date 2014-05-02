package main

import (
	"github.com/elazarl/goproxy"

	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	appendLog int = iota
	reopenLog int = iota
)

// Digest auth. operation type
const (
	validateUser int = iota
	getNonce     int = iota
)

// Digest auth. resp status
const (
	authOk     int = iota
	authFailed int = iota
	nonceOk    int = iota
)

const proxyForwardedForHeader = "X-Forwarded-For"

type Meta struct {
	action int
	req    *http.Request
	resp   *http.Response
	err    error
	time   time.Time
}

type BasicAuthRequest struct {
	data        *BasicAuthData
	respChannel chan *BasicAuthResponse
}

type BasicAuthResponse struct {
	status bool
}

type DigestAuthRequest struct {
	data        *DigestAuthData
	op          int
	respChannel chan *DigestAuthResponse
}

type DigestAuthResponse struct {
	data   string
	status int
}

func makeBasicAuthValidator(auth *BasicAuth) BasicAuthFunc {
	channel := make(chan *BasicAuthRequest)
	validator := func() {
		for e := range channel {
			status := auth.Validate(e.data)
			e.respChannel <- &BasicAuthResponse{status}
		}
	}

	go validator()

	return func(authData *BasicAuthData) *BasicAuthResponse {
		request := &BasicAuthRequest{authData, make(chan *BasicAuthResponse)}
		channel <- request
		return <-request.respChannel
	}
}

func makeDigestAuthValidator(auth *DigestAuth) DigestAuthFunc {
	channel := make(chan *DigestAuthRequest)
	processor := func() {
		for e := range channel {
			var response *DigestAuthResponse
			switch e.op {
			case validateUser:
				status := auth.Validate(e.data)
				if status {
					response = &DigestAuthResponse{status: authOk}
				} else {
					response = &DigestAuthResponse{status: authFailed}
				}
			case getNonce:
				nonce := auth.NewNonce()
				response = &DigestAuthResponse{status: nonceOk, data: nonce}
			default:
				panic("unexpected operation type")
			}
			e.respChannel <- response
		}
	}

	go processor()

	f := func(authData *DigestAuthData, op int) *DigestAuthResponse {
		request := &DigestAuthRequest{data: authData, op: op, respChannel: make(chan *DigestAuthResponse)}
		channel <- request
		return <-request.respChannel
	}

	return f
}

func fprintf(nr *int64, err *error, w io.Writer, pat string, a ...interface{}) {
	if *err != nil {
		return
	}
	var n int
	n, *err = fmt.Fprintf(w, pat, a...)
	*nr += int64(n)
}

func write(nr *int64, err *error, w io.Writer, b []byte) {
	if *err != nil {
		return
	}
	var n int
	n, *err = w.Write(b)
	*nr += int64(n)
}

func (m *Meta) WriteTo(w io.Writer) (nr int64, err error) {
	if m.resp != nil {
		if m.resp.Request != nil {
			fprintf(&nr, &err, w,
				"%v %v %v %v %v %v\n",
				m.time.Format(time.RFC3339),
				m.resp.Request.RemoteAddr,
				m.resp.Request.Method,
				m.resp.Request.URL,
				m.resp.StatusCode,
				m.resp.ContentLength)
		} else {
			fprintf(&nr, &err, w,
				"%v %v %v %v %v %v\n",
				m.time.Format(time.RFC3339),
				"-",
				"-",
				"-",
				m.resp.StatusCode,
				m.resp.ContentLength)
		}
	} else if m.req != nil {
		fprintf(&nr, &err, w,
			"%v %v %v %v %v %v\n",
			m.time.Format(time.RFC3339),
			m.req.RemoteAddr,
			m.req.Method,
			m.req.URL,
			"-",
			"-")
	}

	return
}

type HttpLogger struct {
	path        string
	logChannel  chan *Meta
	errorChanel chan error
}

func NewLogger(conf *Configuration) *HttpLogger {
	var fh *os.File

	if conf.AccessLog != "" {
		var err error
		fh, err = os.OpenFile(conf.AccessLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalf("Couldn't open log file: %v", err)
		}
	}

	logger := &HttpLogger{conf.AccessLog, make(chan *Meta), make(chan error)}

	go func() {
		for m := range logger.logChannel {
			if fh != nil {
				switch m.action {
				case appendLog:
					if _, err := m.WriteTo(fh); err != nil {
						log.Println("Can't write meta", err)
					}
				case reopenLog:
					fh.Close()
					var err error
					fh, err = os.OpenFile(conf.AccessLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
					if err != nil {
						log.Fatalf("Couldn't reopen log file: %v", err)
					}
				}
			}
		}
		logger.errorChanel <- fh.Close()
	}()

	return logger
}

var emptyResp = &http.Response{}
var emptyReq = &http.Request{}

func (logger *HttpLogger) LogReq(req *http.Request, ctx *goproxy.ProxyCtx) {
	if req == nil {
		req = emptyReq
	}

	logger.LogMeta(&Meta{
		action: appendLog,
		req:    req,
		err:    ctx.Error,
		time:   time.Now()})
}

func (logger *HttpLogger) LogResp(resp *http.Response, ctx *goproxy.ProxyCtx) {
	if resp == nil {
		resp = emptyResp
	}

	logger.LogMeta(&Meta{
		action: appendLog,
		resp:   resp,
		err:    ctx.Error,
		time:   time.Now()})
}

func (logger *HttpLogger) LogMeta(m *Meta) {
	logger.logChannel <- m
}

func (logger *HttpLogger) Close() error {
	close(logger.logChannel)
	return <-logger.errorChanel
}

func (logger *HttpLogger) Reopen() {
	logger.LogMeta(&Meta{action: reopenLog})
}

func setAllowedNetworksHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer) {
	if conf.AllowedNetworks != nil && len(conf.AllowedNetworks) > 0 {
		proxy.OnRequest(goproxy.Not(sourceIpMatches(conf.AllowedNetworks))).HandleConnect(goproxy.AlwaysReject)
		proxy.OnRequest(goproxy.Not(sourceIpMatches(conf.AllowedNetworks))).DoFunc(
			func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				return req, goproxy.NewResponse(req, goproxy.ContentTypeHtml, http.StatusForbidden, "Access denied")
			})
	}

	if conf.DisallowedNetworks != nil && len(conf.DisallowedNetworks) > 0 {
		proxy.OnRequest(sourceIpMatches(conf.DisallowedNetworks)).HandleConnect(goproxy.AlwaysReject)
		proxy.OnRequest(sourceIpMatches(conf.DisallowedNetworks)).DoFunc(
			func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				return req, goproxy.NewResponse(req, goproxy.ContentTypeHtml, http.StatusForbidden, "Access denied")
			})
	}
}

func sourceIpMatches(networks []string) goproxy.ReqConditionFunc {
	cidrs := make([](*net.IPNet), len(networks))
	for idx, network := range networks {
		_, cidrnet, _ := net.ParseCIDR(network)
		cidrs[idx] = cidrnet
	}

	return func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			ctx.Warnf("coudn't parse remote address %v: %v", req.RemoteAddr, err)
			return false
		}
		addr := net.ParseIP(ip)
		for _, network := range cidrs {
			if network.Contains(addr) {
				return true
			}
		}
		return false
	}
}

func setAllowedConnectPortsHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer) {
	if conf.AllowedConnectPorts != nil && len(conf.AllowedConnectPorts) > 0 {
		ports := make([]string, len(conf.AllowedConnectPorts))
		for i, v := range conf.AllowedConnectPorts {
			ports[i] = ":" + v
		}
		rx := "(" + strings.Join(ports, "|") + ")$"
		proxy.OnRequest(goproxy.Not(goproxy.ReqHostMatches(regexp.MustCompile(rx)))).HandleConnect(goproxy.AlwaysReject)
	}
}

func setForwardedForHeaderHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer) {
	f := func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			ctx.Warnf("coudn't parse remote address %v: %v", req.RemoteAddr, err)
			return req, nil
		}

		switch conf.ForwardedFor {
		case "on":
			header := req.Header.Get(proxyForwardedForHeader)
			if header == "" {
				req.Header.Add(proxyForwardedForHeader, ip)
			} else {
				header = header + ", " + ip
				req.Header.Del(proxyForwardedForHeader)
				req.Header.Add(proxyForwardedForHeader, header)
			}
		case "delete":
			req.Header.Del(proxyForwardedForHeader)
		case "truncate":
			req.Header.Del(proxyForwardedForHeader)
			req.Header.Add(proxyForwardedForHeader, ip)
		}

		return req, nil
	}

	proxy.OnRequest().DoFunc(f)
}

func makeCustomDial(localAddr *net.TCPAddr) func(string, string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		remoteAddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, err
		}
		c, err := net.DialTCP(network, localAddr, remoteAddr)
		return c, err
	}
}

func createProxy(conf *Configuration) *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	setActivityLog(conf, proxy)

	if conf.BindIP != "" {
		var laddr string
		addressOk := true
		if ip := net.ParseIP(conf.BindIP); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				laddr = conf.BindIP + ":0"
			} else if ip16 := ip.To16(); ip16 != nil {
				laddr = "[" + conf.BindIP + "]:0"
			} else {
				proxy.Logger.Printf("[WARN] couldn't use \"%v\" as outgoing request address.\n", conf.BindIP)
				addressOk = false
			}
		}
		if addressOk {
			if addr, err := net.ResolveTCPAddr("tcp", laddr); err == nil {
				proxy.Tr.Dial = makeCustomDial(addr)
			} else {
				proxy.Logger.Printf("[WARN] couldn't use \"%v\" as outgoing request address. %v\n", conf.BindIP, err)
			}
		}
	}

	return proxy
}

func setActivityLog(conf *Configuration, proxy *goproxy.ProxyHttpServer) {
	if conf.ActivityLog != "" {
		fh, err := os.OpenFile(conf.ActivityLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalf("couldn't open activity log file %v: %v", conf.ActivityLog, err)
		}
		proxy.Logger = log.New(fh, "", log.LstdFlags)
	}
}

func main() {
	config := flag.String("config", "microproxy.json", "proxy configuration file")
	verbose := flag.Bool("v", false, "enable verbose debug mode")

	flag.Parse()

	conf := NewConfiguration(*config)

	proxy := createProxy(conf)
	proxy.Verbose = *verbose

	logger := NewLogger(conf)

	if conf.AuthFile != "" {
		if conf.AuthType == "basic" {
			auth, err := NewBasicAuthFromFile(conf.AuthFile)
			if err != nil {
				proxy.Logger.Fatalf("couldn't create basic auth structure: %v\n", err)
			}
			ProxyBasic(proxy, conf.AuthRealm, makeBasicAuthValidator(auth))
		} else {
			auth, err := NewDigestAuthFromFile(conf.AuthFile)
			if err != nil {
				proxy.Logger.Fatalf("couldn't create digest auth structure: %v\n", err)
			}
			ProxyDigest(proxy, conf.AuthRealm, makeDigestAuthValidator(auth))
		}
	}

	proxy.OnRequest().HandleConnectFunc(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			if ctx.Req == nil {
				ctx.Req = emptyReq
			}

			logger.LogMeta(&Meta{
				action: appendLog,
				req:    ctx.Req,
				err:    ctx.Error,
				time:   time.Now()})

			return goproxy.OkConnect, host
		})

	setAllowedConnectPortsHandler(conf, proxy)
	setAllowedNetworksHandler(conf, proxy)
	setForwardedForHeaderHandler(conf, proxy)

	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			logger.LogResp(resp, ctx)
			return resp
		})

	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGUSR1)

	go func() {
		for {
			sig := <-signalChannel
			switch sig {
			case os.Interrupt:
				proxy.Logger.Println("got interrupt signal, exiting")
				logger.Close()
				os.Exit(0)
			case syscall.SIGUSR1:
				proxy.Logger.Println("got USR1 signal, reopening logs")
				// Reopen access log
				logger.Reopen()
				// Reopen activity log
				setActivityLog(conf, proxy)
			}
		}
	}()

	proxy.Logger.Println("starting proxy")

	log.Fatal(http.ListenAndServe(conf.Listen, proxy))
}
