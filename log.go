package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/elazarl/goproxy"
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
	path         string
	logChannel   chan *logData
	errorChannel chan error
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
		fh, err = os.OpenFile(conf.AccessLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			log.Fatalf("Couldn't open log file: %v", err)
		}
	}

	logger := &proxyLogger{
		path:         conf.AccessLog,
		logChannel:   make(chan *logData),
		errorChannel: make(chan error),
	}

	go func() {
		for m := range logger.logChannel {
			if fh != nil {
				switch m.action {
				case appendLog:
					if _, err := m.writeTo(fh); err != nil {
						log.Println("Can't write meta", err)
					}
				case reopenLog:
					err := fh.Close()
					if err != nil {
						log.Fatal(err)
					}
					fh, err = os.OpenFile(conf.AccessLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
					if err != nil {
						log.Fatalf("Couldn't reopen log file: %v", err)
					}
				}
			}
		}
		logger.errorChannel <- fh.Close()
	}()

	return logger
}

func (logger *proxyLogger) logRequest(req *http.Request, ctx *goproxy.ProxyCtx) {
	if req == nil {
		req = emptyReq
	}

	logger.writeLogEntry(&logData{
		action: appendLog,
		req:    req,
		err:    ctx.Error,
		time:   time.Now(),
	})
}

func (logger *proxyLogger) logResponse(resp *http.Response, ctx *goproxy.ProxyCtx) {
	if resp == nil {
		resp = emptyResp
	}

	logger.writeLogEntry(&logData{
		action: appendLog,
		resp:   resp,
		user:   getAuthenticatedUserName(ctx),
		err:    ctx.Error,
		time:   time.Now(),
	})
}

func (logger *proxyLogger) writeLogEntry(data *logData) {
	logger.logChannel <- data
}

func (logger *proxyLogger) log(ctx *goproxy.ProxyCtx) {
	data := &logData{
		action: appendLog,
		req:    ctx.Req,
		resp:   ctx.Resp,
		user:   getAuthenticatedUserName(ctx),
		err:    ctx.Error,
		time:   time.Now(),
	}
	logger.writeLogEntry(data)
}

func (logger *proxyLogger) close() error {
	close(logger.logChannel)
	return <-logger.errorChannel
}

func (logger *proxyLogger) reopen() {
	logger.writeLogEntry(&logData{action: reopenLog})
}
