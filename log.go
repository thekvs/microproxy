package main

import (
	"github.com/elazarl/goproxy"

	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	appendLog int = iota
	reopenLog int = iota
)

var (
	emptyResp = &http.Response{}
	emptyReq  = &http.Request{}
)

type logData struct {
	action int
	req    *http.Request
	resp   *http.Response
	user   string
	err    error
	time   time.Time
}

type proxyLogger struct {
	path        string
	logChannel  chan *logData
	errorChanel chan error
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

func getAuthenticatedUserName(ctx *goproxy.ProxyCtx) string {
	user, ok := ctx.UserData.(string)
	if !ok {
		user = "-"
	}

	return user
}

func (m *logData) writeTo(w io.Writer) (nr int64, err error) {
	if m.resp != nil {
		if m.resp.Request != nil {
			fprintf(&nr, &err, w,
				"%v %v %v %v %v %v %v\n",
				m.time.Format(time.RFC3339),
				m.resp.Request.RemoteAddr,
				m.resp.Request.Method,
				m.resp.Request.URL,
				m.resp.StatusCode,
				m.resp.ContentLength,
				m.user)
		} else {
			fprintf(&nr, &err, w,
				"%v %v %v %v %v %v %v\n",
				m.time.Format(time.RFC3339),
				"-",
				"-",
				"-",
				m.resp.StatusCode,
				m.resp.ContentLength,
				m.user)
		}
	} else if m.req != nil {
		fprintf(&nr, &err, w,
			"%v %v %v %v %v %v %v\n",
			m.time.Format(time.RFC3339),
			m.req.RemoteAddr,
			m.req.Method,
			m.req.URL,
			"-",
			"-",
			m.user)
	}

	return
}

func newProxyLogger(conf *configuration) *proxyLogger {
	var fh *os.File

	if conf.AccessLog != "" {
		var err error
		fh, err = os.OpenFile(conf.AccessLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalf("Couldn't open log file: %v", err)
		}
	}

	logger := &proxyLogger{conf.AccessLog, make(chan *logData), make(chan error)}

	go func() {
		for m := range logger.logChannel {
			if fh != nil {
				switch m.action {
				case appendLog:
					if _, err := m.writeTo(fh); err != nil {
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

func (logger *proxyLogger) logRequest(req *http.Request, ctx *goproxy.ProxyCtx) {
	if req == nil {
		req = emptyReq
	}

	logger.logMeta(&logData{
		action: appendLog,
		req:    req,
		err:    ctx.Error,
		time:   time.Now()})
}

func (logger *proxyLogger) logResponse(resp *http.Response, ctx *goproxy.ProxyCtx) {
	if resp == nil {
		resp = emptyResp
	}

	logger.logMeta(&logData{
		action: appendLog,
		resp:   resp,
		user:   getAuthenticatedUserName(ctx),
		err:    ctx.Error,
		time:   time.Now()})
}

func (logger *proxyLogger) logMeta(m *logData) {
	logger.logChannel <- m
}

func (logger *proxyLogger) log(ctx *goproxy.ProxyCtx) {
	meta := &logData{
		action: appendLog,
		req:    ctx.Req,
		resp:   ctx.Resp,
		user:   getAuthenticatedUserName(ctx),
		err:    ctx.Error,
		time:   time.Now(),
	}
	logger.logMeta(meta)
}

func (logger *proxyLogger) close() error {
	close(logger.logChannel)
	return <-logger.errorChanel
}

func (logger *proxyLogger) reopen() {
	logger.logMeta(&logData{action: reopenLog})
}
