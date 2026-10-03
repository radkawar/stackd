package elbv2

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// connectionIdlePolicy applies the configured inactivity interval to bytes on
// both client and target sockets, including uploads and streaming responses.
// Updates reschedule already-open sockets without replacing their native node.
type connectionIdlePolicy struct {
	mu          sync.Mutex
	timeout     time.Duration
	connections map[*idleConnection]struct{}
}
type idleConnection struct {
	net.Conn
	policy                         *connectionIdlePolicy
	timer                          *time.Timer
	last                           time.Time
	closed                         bool
	expired                        bool
	client                         bool
	secure                         bool
	active                         bool
	input                          bool
	response                       net.Conn
	tlsState                       *tls.ConnectionState
	reading, writing, bodyTimedOut bool
	readAt, writeAt                time.Time
}

func newConnectionIdlePolicy(timeout time.Duration) *connectionIdlePolicy {
	return &connectionIdlePolicy{timeout: timeout, connections: map[*idleConnection]struct{}{}}
}
func (p *connectionIdlePolicy) wrap(conn net.Conn) net.Conn {
	c := &idleConnection{Conn: conn, policy: p, last: time.Now()}
	p.mu.Lock()
	p.connections[c] = struct{}{}
	c.timer = time.AfterFunc(p.timeout, c.expire)
	p.mu.Unlock()
	return c
}
func (p *connectionIdlePolicy) setTimeout(timeout time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timeout == timeout {
		return
	}
	p.timeout = timeout
	for c := range p.connections {
		if !c.active {
			c.timer.Reset(time.Until(c.last.Add(timeout)))
		}
		if c.reading {
			_ = c.Conn.SetReadDeadline(c.readAt.Add(timeout))
		}
		if c.writing {
			_ = c.Conn.SetWriteDeadline(c.writeAt.Add(timeout))
		}
	}
}
func (p *connectionIdlePolicy) close() {
	p.mu.Lock()
	all := make([]*idleConnection, 0, len(p.connections))
	for c := range p.connections {
		all = append(all, c)
	}
	p.mu.Unlock()
	for _, c := range all {
		_ = c.Close()
	}
}
func (c *idleConnection) expire() {
	p := c.policy
	p.mu.Lock()
	if c.closed || c.active {
		p.mu.Unlock()
		return
	}
	remaining := time.Until(c.last.Add(p.timeout))
	if remaining > 0 {
		c.timer.Reset(remaining)
		p.mu.Unlock()
		return
	}
	c.closed, c.expired = true, true
	response, timeout := c.response, p.timeout
	if !c.client || !c.input {
		response = nil
	}
	delete(p.connections, c)
	p.mu.Unlock()
	// Before request headers are complete, net/http has no ResponseWriter.
	// Emit one timeout response only when an HTTP transport is established;
	// active requests instead let the HTTP layer classify their failing leg.
	if response != nil {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(timeout))
		_, _ = response.Write([]byte("HTTP/1.1 408 Request Timeout\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 15\r\nConnection: close\r\n\r\nRequest Timeout"))
	}
	_ = c.Conn.Close()
}
func (c *idleConnection) touch() {
	p := c.policy
	p.mu.Lock()
	if !c.closed {
		c.last = time.Now()
		if !c.active {
			c.timer.Reset(p.timeout)
		}
	}
	p.mu.Unlock()
}
func (c *idleConnection) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && !c.secure {
		c.touch()
	}
	c.policy.mu.Lock()
	if c.client && n > 0 {
		c.input = true
		if c.reading {
			c.readAt = time.Now()
			_ = c.Conn.SetReadDeadline(c.readAt.Add(c.policy.timeout))
		}
	}
	var timeout net.Error
	if c.client && c.reading && errors.As(err, &timeout) && timeout.Timeout() {
		c.bodyTimedOut = true
	}
	expired := c.expired
	c.policy.mu.Unlock()
	if err != nil && expired {
		err = idleTimeoutError{err}
	}
	return n, err
}
func (c *idleConnection) Write(b []byte) (int, error) {
	p := c.policy
	p.mu.Lock()
	if c.client && c.active {
		c.writing, c.writeAt = true, time.Now()
		_ = c.Conn.SetWriteDeadline(c.writeAt.Add(p.timeout))
	}
	p.mu.Unlock()
	n, err := c.Conn.Write(b)
	if n > 0 && !c.secure {
		c.touch()
	}
	p.mu.Lock()
	if c.writing {
		c.writing = false
		_ = c.Conn.SetWriteDeadline(time.Time{})
	}
	expired := c.expired
	p.mu.Unlock()
	if err != nil && expired {
		err = idleTimeoutError{err}
	}
	return n, err
}

type idleTimeoutError struct{ error }

func (idleTimeoutError) Timeout() bool   { return true }
func (idleTimeoutError) Temporary() bool { return false }
func (e idleTimeoutError) Unwrap() error { return e.error }
func (c *idleConnection) Close() error {
	p := c.policy
	p.mu.Lock()
	if !c.closed {
		c.closed = true
		c.timer.Stop()
		delete(p.connections, c)
	}
	p.mu.Unlock()
	return c.Conn.Close()
}
func (c *idleConnection) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}
