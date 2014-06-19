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

type Meta struct {
	action int
	req    *http.Request
	resp   *http.Response
	err    error
	time   time.Time
}

type HttpLogger struct {
	path        string
	logChannel  chan *Meta
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

func (m *Meta) writeTo(w io.Writer) (nr int64, err error) {
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

func (logger *HttpLogger) logRequest(req *http.Request, ctx *goproxy.ProxyCtx) {
	if req == nil {
		req = emptyReq
	}

	logger.logMeta(&Meta{
		action: appendLog,
		req:    req,
		err:    ctx.Error,
		time:   time.Now()})
}

func (logger *HttpLogger) logResponse(resp *http.Response, ctx *goproxy.ProxyCtx) {
	if resp == nil {
		resp = emptyResp
	}

	logger.logMeta(&Meta{
		action: appendLog,
		resp:   resp,
		err:    ctx.Error,
		time:   time.Now()})
}

func (logger *HttpLogger) logMeta(m *Meta) {
	logger.logChannel <- m
}

func (logger *HttpLogger) close() error {
	close(logger.logChannel)
	return <-logger.errorChanel
}

func (logger *HttpLogger) reopen() {
	logger.logMeta(&Meta{action: reopenLog})
}
