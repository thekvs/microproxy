package main

import (
	"net"
	"time"
)

const (
	DefaultReadTimeout  = 15 * time.Minute
	DefaultWriteTimeout = 15 * time.Minute
)

type TimedConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (c TimedConn) Read(b []byte) (int, error) {
	err := c.Conn.SetReadDeadline(time.Now().Add(c.readTimeout))
	if err != nil {
		return 0, err
	}

	return c.Conn.Read(b)
}

func (c TimedConn) Write(b []byte) (int, error) {
	err := c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	if err != nil {
		return 0, err
	}

	return c.Conn.Write(b)
}
