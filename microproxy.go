package main

import (
	"github.com/elazarl/goproxy"

	"flag"
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

const proxyForwardedForHeader = "X-Forwarded-For"
const tcpKeepAliveInterval = 1 * time.Minute

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
			status := auth.validate(e.data)
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
			request := &DigestAuthRequest{op: maintPing, respChannel: make(chan *DigestAuthResponse)}
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
		request := &DigestAuthRequest{data: authData, op: op, respChannel: make(chan *DigestAuthResponse)}
		channel <- request
		return <-request.respChannel
	}

	return authFunc
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

		conn, err := net.DialTCP(network, localAddr, remoteAddr)
		if err == nil {
			conn.SetKeepAlive(true)
			conn.SetKeepAlivePeriod(tcpKeepAliveInterval)
		}

		c := TConn{
			Conn:         conn,
			readTimeout:  defaultReadTimeout,
			writeTimeout: defaultWriteTimeout,
		}

		return c, err
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
				proxy.Tr.Dial = makeCustomDial(addr)
			} else {
				proxy.Logger.Printf("WARN: couldn't use \"%v\" as outgoing request address. %v\n", conf.BindIP, err)
			}
		} else {
			proxy.Tr.Dial = makeCustomDial(nil)
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

func setSignalHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer, logger *HttpLogger) {
	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGUSR1)

	go func() {
		for {
			sig := <-signalChannel
			switch sig {
			case os.Interrupt:
				proxy.Logger.Println("got interrupt signal, exiting")
				logger.close()
				os.Exit(0)
			case syscall.SIGUSR1:
				proxy.Logger.Println("got USR1 signal, reopening logs")
				// reopen access log
				logger.reopen()
				// reopen activity log
				setActivityLog(conf, proxy)
			}
		}
	}()
}

func setAuthenticationHandler(conf *Configuration, proxy *goproxy.ProxyHttpServer, logger *HttpLogger) {
	if conf.AuthFile != "" {
		if conf.AuthType == "basic" {
			auth, err := NewBasicAuthFromFile(conf.AuthFile)
			if err != nil {
				proxy.Logger.Fatalf("couldn't create basic auth structure: %v\n", err)
			}
			setProxyBasicAuth(proxy, conf.AuthRealm, makeBasicAuthValidator(auth), logger)
		} else {
			auth, err := NewDigestAuthFromFile(conf.AuthFile)
			if err != nil {
				proxy.Logger.Fatalf("couldn't create digest auth structure: %v\n", err)
			}
			setProxyDigestAuth(proxy, conf.AuthRealm, makeDigestAuthValidator(auth), logger)
		}
	} else {
		// If there is neither Digest no Basic authentication we still need to setup
		// handler to log HTTPS CONNECT requests
		setHTTPSLoggingHandler(proxy, logger)
	}
}

func setHTTPSLoggingHandler(proxy *goproxy.ProxyHttpServer, logger *HttpLogger) {
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

func setHTTPLoggingHandler(proxy *goproxy.ProxyHttpServer, logger *HttpLogger) {
	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			logger.logResponse(resp, ctx)
			return resp
		})
}

func main() {
	config := flag.String("config", "microproxy.json", "proxy configuration file")
	verbose := flag.Bool("v", false, "enable verbose debug mode")

	flag.Parse()

	conf := NewConfiguration(*config)

	proxy := createProxy(conf)
	proxy.Verbose = *verbose

	logger := NewLogger(conf)

	setHTTPLoggingHandler(proxy, logger)
	setAllowedConnectPortsHandler(conf, proxy)
	setAllowedNetworksHandler(conf, proxy)
	setForwardedForHeaderHandler(conf, proxy)
	setSignalHandler(conf, proxy, logger)

	// To be called first while processing handlers' stack,
	// has to be placed last in the source code.
	setAuthenticationHandler(conf, proxy, logger)

	proxy.Logger.Println("starting proxy")

	log.Fatal(http.ListenAndServe(conf.Listen, proxy))
}
