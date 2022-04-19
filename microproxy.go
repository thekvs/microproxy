package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
)

// Digest auth. operation type
const (
	validateUser int = iota
	getNonce     int = iota
	maintPing    int = iota
)

// Digest auth. resp status
const (
	authOk     int = iota
	authFailed int = iota
	nonceOk    int = iota
	maintOk    int = iota
)

const (
	proxyForwardedForHeader = "X-Forwarded-For"
	proxyViaHeader          = "Via"
)

const tcpKeepAliveInterval = 1 * time.Minute

type basicAuthRequest struct {
	data        *BasicAuthData
	respChannel chan *BasicAuthResponse
}

type BasicAuthResponse struct {
	status bool
}

type digestAuthRequest struct {
	data        *DigestAuthData
	op          int
	respChannel chan *DigestAuthResponse
}

type DigestAuthResponse struct {
	data   string
	status int
}

func makeBasicAuthValidator(auth *basicAuth) BasicAuthFunc {
	channel := make(chan *basicAuthRequest)
	validator := func() {
		for e := range channel {
			status := auth.validate(e.data)
			e.respChannel <- &BasicAuthResponse{status: status}
		}
	}

	go validator()

	return func(authData *BasicAuthData) *BasicAuthResponse {
		request := &basicAuthRequest{
			data:        authData,
			respChannel: make(chan *BasicAuthResponse),
		}
		channel <- request
		return <-request.respChannel
	}
}

func makeDigestAuthValidator(auth *DigestAuth) DigestAuthFunc {
	channel := make(chan *digestAuthRequest)

	processor := func() {
		for e := range channel {
			var response *DigestAuthResponse
			switch e.op {
			case validateUser:
				status := auth.validate(e.data)
				if status {
					response = &DigestAuthResponse{status: authOk}
				} else {
					response = &DigestAuthResponse{status: authFailed}
				}
			case getNonce:
				nonce := auth.newNonce()
				response = &DigestAuthResponse{status: nonceOk, data: nonce}
			case maintPing:
				auth.expireNonces()
				response = &DigestAuthResponse{status: maintOk}
			default:
				panic("unexpected operation type")
			}
			e.respChannel <- response
		}
	}

	maintPinger := func() {
		for {
			request := &digestAuthRequest{op: maintPing, respChannel: make(chan *DigestAuthResponse)}
			channel <- request
			response := <-request.respChannel
			if response.status != maintOk {
				log.Fatal("unexpected status")
			}
			time.Sleep(30 * time.Minute)
		}
	}

	go processor()
	go maintPinger()

	authFunc := func(authData *DigestAuthData, op int) *DigestAuthResponse {
		request := &digestAuthRequest{data: authData, op: op, respChannel: make(chan *DigestAuthResponse)}
		channel <- request
		return <-request.respChannel
	}

	return authFunc
}

func setAllowedNetworksHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer) {
	if conf.AllowedNetworks != nil && len(conf.AllowedNetworks) > 0 {
		proxy.OnRequest(goproxy.Not(sourceIPMatches(conf.AllowedNetworks))).HandleConnect(goproxy.AlwaysReject)
		proxy.OnRequest(goproxy.Not(sourceIPMatches(conf.AllowedNetworks))).DoFunc(
			func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				return req, goproxy.NewResponse(req, goproxy.ContentTypeHtml, http.StatusForbidden, "Access denied")
			})
	}

	if conf.DisallowedNetworks != nil && len(conf.DisallowedNetworks) > 0 {
		proxy.OnRequest(sourceIPMatches(conf.DisallowedNetworks)).HandleConnect(goproxy.AlwaysReject)
		proxy.OnRequest(sourceIPMatches(conf.DisallowedNetworks)).DoFunc(
			func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				return req, goproxy.NewResponse(req, goproxy.ContentTypeHtml, http.StatusForbidden, "Access denied")
			})
	}
}

func sourceIPMatches(networks []string) goproxy.ReqConditionFunc {
	cidrs := make([](*net.IPNet), len(networks))
	for idx, network := range networks {
		_, cidrnet, _ := net.ParseCIDR(network)
		cidrs[idx] = cidrnet
	}

	return func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			ctx.Warnf("couldn't parse remote address %v: %v", req.RemoteAddr, err)
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
			ports[i] = ":" + strconv.Itoa(v)
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

		switch conf.ForwardedForHeader {
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

func setViaHeaderHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer) {
	handler := func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		switch conf.ViaHeader {
		case "on":
			header := req.Header.Get(proxyViaHeader)
			if header == "" {
				header = fmt.Sprintf("1.1 %s", conf.ViaProxyName)
			} else {
				header = fmt.Sprintf("%s, 1.1 %s", header, conf.ViaProxyName)
			}
			req.Header.Add(proxyViaHeader, header)
		case "delete":
			req.Header.Del(proxyViaHeader)
		}
		return req, nil
	}

	proxy.OnRequest().DoFunc(handler)
}

func setAddCustomHeadersHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer) {
	handler := func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		for _, headerData := range conf.AddHeaders {
			if len(headerData) == 2 {
				header := headerData[0]
				value := headerData[1]
				if len(header) > 0 && len(value) > 0 {
					headerExists := (req.Header.Get(header) != "")
					if !headerExists {
						req.Header.Add(header, value)
					}
				}
			}
		}
		return req, nil
	}

	if len(conf.AddHeaders) > 0 {
		proxy.OnRequest().DoFunc(handler)
	}
}

func makeCustomDialContext(localAddr *net.TCPAddr) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		remoteAddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, err
		}

		conn, err := net.DialTCP(network, localAddr, remoteAddr)
		if err != nil {
			return nil, err
		}

		err = conn.SetKeepAlive(true)
		if err != nil {
			return nil, err
		}

		err = conn.SetKeepAlivePeriod(tcpKeepAliveInterval)
		if err != nil {
			return nil, err
		}

		c := TimedConn{
			Conn:         conn,
			readTimeout:  DefaultReadTimeout,
			writeTimeout: DefaultWriteTimeout,
		}

		return c, nil
	}
}

func makeCustomDial(localAddr *net.TCPAddr) func(string, string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		remoteAddr, err := net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, err
		}

		conn, err := net.DialTCP(network, localAddr, remoteAddr)
		if err != nil {
			return nil, err
		}

		err = conn.SetKeepAlive(true)
		if err != nil {
			return nil, err
		}

		err = conn.SetKeepAlivePeriod(tcpKeepAliveInterval)
		if err != nil {
			return nil, err
		}

		c := TimedConn{
			Conn:         conn,
			readTimeout:  DefaultReadTimeout,
			writeTimeout: DefaultWriteTimeout,
		}

		return c, nil
	}
}

func createProxy(conf *Configuration) *goproxy.ProxyHttpServer {
	proxy := goproxy.NewProxyHttpServer()
	setActivityLog(conf, proxy)

	var laddr string

	addressOk := true

	if conf.BindIP != "" {
		if ip := net.ParseIP(conf.BindIP); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				laddr = conf.BindIP + ":0"
			} else if ip16 := ip.To16(); ip16 != nil {
				laddr = "[" + conf.BindIP + "]:0"
			} else {
				proxy.Logger.Printf("WARN: couldn't use \"%v\" as outgoing request address.\n", conf.BindIP)
				addressOk = false
			}
		}
	}

	if addressOk {
		if laddr != "" {
			if addr, err := net.ResolveTCPAddr("tcp", laddr); err == nil {
				proxy.Tr.DialContext = makeCustomDialContext(addr)
				proxy.Tr.Dial = makeCustomDial(addr)
				proxy.ConnectDial = makeCustomDial(addr)
			} else {
				proxy.Logger.Printf("WARN: couldn't use \"%v\" as outgoing request address. %v\n", conf.BindIP, err)
			}
		} else {
			proxy.Tr.DialContext = makeCustomDialContext(nil)
		}
	}

	return proxy
}

func setActivityLog(conf *Configuration, proxy *goproxy.ProxyHttpServer) {
	if conf.ActivityLog != "" {
		fh, err := os.OpenFile(conf.ActivityLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			log.Fatalf("couldn't open activity log file %v: %v", conf.ActivityLog, err)
		}
		proxy.Logger = log.New(fh, "", log.LstdFlags)
	}
}

func setSignalHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer, logger *ProxyLogger) {
	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)

	signalHandler := func() {
		for sig := range signalChannel {
			switch sig {
			case os.Interrupt, syscall.SIGTERM:
				proxy.Logger.Printf("got interrupt signal, exiting\n")
				err := logger.close()
				if err != nil {
					log.Printf("Close error: %v", err)
				}
				os.Exit(0)
			case syscall.SIGUSR1:
				proxy.Logger.Printf("got USR1 signal, reopening logs\n")
				// reopen access log
				logger.reopen()
				// reopen activity log
				setActivityLog(conf, proxy)
			}
		}
	}

	go signalHandler()
}

func setAuthenticationHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer, logger *ProxyLogger) {
	if conf.AuthFile != "" {
		if conf.AuthType == "basic" {
			auth, err := newBasicAuthFromFile(conf.AuthFile)
			if err != nil {
				proxy.Logger.Printf("couldn't create basic auth structure: %v\n", err)
				os.Exit(1)
			}
			setProxyBasicAuth(proxy, conf.AuthRealm, makeBasicAuthValidator(auth), logger)
		} else {
			auth, err := newDigestAuthFromFile(conf.AuthFile)
			if err != nil {
				proxy.Logger.Printf("couldn't create digest auth structure: %v\n", err)
				os.Exit(1)
			}
			setProxyDigestAuth(proxy, conf.AuthRealm, makeDigestAuthValidator(auth), logger)
		}
	} else {
		// If there is neither Digest no Basic authentication we still need to setup
		// handler to log HTTPS CONNECT requests
		setHTTPSLoggingHandler(proxy, logger)
	}
}

func setHTTPSLoggingHandler(proxy *goproxy.ProxyHttpServer, logger *ProxyLogger) {
	proxy.OnRequest().HandleConnectFunc(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			if ctx.Req == nil {
				ctx.Req = emptyReq
			}

			if logger != nil {
				logger.log(ctx)
			}

			return goproxy.OkConnect, host
		})
}

func setHTTPLoggingHandler(proxy *goproxy.ProxyHttpServer, logger *ProxyLogger) {
	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			logger.logResponse(resp, ctx)
			return resp
		})
}

func setForwardProxy(conf *Configuration, proxy *goproxy.ProxyHttpServer) {
	if len(conf.ForwardProxyURL) == 0 {
		return
	}

	u, err := url.Parse(conf.ForwardProxyURL)
	if err != nil {
		proxy.Logger.Printf("can't parse forward proxy URL: %v", err)
		os.Exit(1)
	}

	proxy.Tr = &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) {
		return url.Parse(conf.ForwardProxyURL)
	}}

	if len(u.User.String()) > 0 {
		connectHandler := func(req *http.Request) {
			req.Header.Del(ProxyAuthorizatonHeader)
			if len(u.User.Username()) > 0 {
				req.Header.Set(ProxyAuthorizatonHeader, "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.String())))
			}
		}
		proxy.ConnectDial = proxy.NewConnectDialToProxyWithHandler(conf.ForwardProxyURL, connectHandler)
	} else {
		proxy.ConnectDial = proxy.NewConnectDialToProxy(conf.ForwardProxyURL)
	}
}

func main() {
	configFile := flag.String("config", "microproxy.toml", "proxy configuration file")
	testConfigOnly := flag.Bool("t", false, "only test configuration file")
	verboseMode := flag.Bool("v", false, "enable verbose debug mode")

	flag.Parse()

	conf := newConfigurationFromFile(*configFile)

	if *testConfigOnly {
		fmt.Println("Configuration file seems ok.")
		os.Exit(0)
	}

	proxy := createProxy(conf)
	proxy.Verbose = *verboseMode

	logger := newProxyLogger(conf)

	setHTTPLoggingHandler(proxy, logger)
	setForwardProxy(conf, proxy)
	setAllowedConnectPortsHandler(conf, proxy)
	setAllowedNetworksHandler(conf, proxy)
	setForwardedForHeaderHandler(conf, proxy)
	setViaHeaderHandler(conf, proxy)
	setAddCustomHeadersHandler(conf, proxy)
	setSignalHandler(conf, proxy, logger)

	// To be called first while processing handlers' stack,
	// has to be placed last in the source code.
	setAuthenticationHandler(conf, proxy, logger)

	proxy.Logger.Printf("starting proxy\n")

	log.Fatal(http.ListenAndServe(conf.Listen, proxy))
}
