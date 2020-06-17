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
	AppendLog int = iota
	ReopenLog int = iota
)

var (
	emptyResp = &http.Response{}
	emptyReq  = &http.Request{}
)

type LogData struct {
	action int
	req    *http.Request
	resp   *http.Response
	user   string
	err    error
	time   time.Time
}

type ProxyLogger struct {
	path         string
	logChannel   chan *LogData
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

func getAuthenticatedUserName(ctx *goproxy.ProxyCtx) string {
	user, ok := ctx.UserData.(string)
	if !ok {
		user = "-"
	}

	return user
}

func (m *LogData) writeTo(w io.Writer) (nr int64, err error) {
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

func newProxyLogger(conf *Configuration) *ProxyLogger {
	var fh *os.File

	if conf.AccessLog != "" {
		var err error
		fh, err = os.OpenFile(conf.AccessLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			log.Fatalf("Couldn't open log file: %v", err)
		}
	}

	logger := &ProxyLogger{
		path:         conf.AccessLog,
		logChannel:   make(chan *LogData),
		errorChannel: make(chan error),
	}

	go func() {
		for m := range logger.logChannel {
			if fh != nil {
				switch m.action {
				case AppendLog:
					if _, err := m.writeTo(fh); err != nil {
						log.Println("Can't write meta", err)
					}
				case ReopenLog:
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

func (logger *ProxyLogger) logResponse(resp *http.Response, ctx *goproxy.ProxyCtx) {
	if resp == nil {
		resp = emptyResp
	}

	logger.writeLogEntry(&LogData{
		action: AppendLog,
		resp:   resp,
		user:   getAuthenticatedUserName(ctx),
		err:    ctx.Error,
		time:   time.Now(),
	})
}

func (logger *ProxyLogger) writeLogEntry(data *LogData) {
	logger.logChannel <- data
}

func (logger *ProxyLogger) log(ctx *goproxy.ProxyCtx) {
	data := &LogData{
		action: AppendLog,
		req:    ctx.Req,
		resp:   ctx.Resp,
		user:   getAuthenticatedUserName(ctx),
		err:    ctx.Error,
		time:   time.Now(),
	}
	logger.writeLogEntry(data)
}

func (logger *ProxyLogger) close() error {
	close(logger.logChannel)
	return <-logger.errorChannel
}

func (logger *ProxyLogger) reopen() {
	logger.writeLogEntry(&LogData{action: ReopenLog})
}
