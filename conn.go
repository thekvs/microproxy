package main

import (
	"net"
	"time"
)

const (
	defaultReadTimeout  = 15 * time.Minute
	defaultWriteTimeout = 15 * time.Minute
)

type TConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (c TConn) Read(b []byte) (int, error) {
	err := c.Conn.SetReadDeadline(time.Now().Add(c.readTimeout))
	if err != nil {
		return 0, err
	}

	return c.Conn.Read(b)
}

func (c TConn) Write(b []byte) (int, error) {
	err := c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	if err != nil {
		return 0, err
	}

	return c.Conn.Write(b)
}
