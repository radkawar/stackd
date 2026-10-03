package elbv2

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type idleListener struct {
	net.Listener
	policy    *connectionIdlePolicy
	tlsConfig *tls.Config
}

func (l idleListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c := &idleConnection{Conn: raw, policy: l.policy, last: time.Now(), client: true, response: raw}
	if l.tlsConfig != nil {
		// Observe encrypted byte activity below TLS, but mark HTTP input only
		// after TLS has yielded plaintext. An incomplete handshake can then
		// close without waiting on TLS's handshake mutex or inventing HTTP.
		c.Conn = tls.Server(tlsActivityConn{Conn: raw, idle: c}, l.tlsConfig)
		c.response = c.Conn
		c.secure = true
	}
	l.policy.mu.Lock()
	l.policy.connections[c] = struct{}{}
	c.timer = time.AfterFunc(l.policy.timeout, c.expire)
	l.policy.mu.Unlock()
	return c, nil
}
func idleHTTPConnection(conn net.Conn) *idleConnection {
	c, _ := conn.(*idleConnection)
	return c
}

type tlsActivityConn struct {
	net.Conn
	idle *idleConnection
}

func (c tlsActivityConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.idle.touch()
	}
	return n, err
}
func (c tlsActivityConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.idle.touch()
	}
	return n, err
}
func (c *idleConnection) requestTLS() *tls.ConnectionState {
	if !c.secure {
		return nil
	}
	c.policy.mu.Lock()
	defer c.policy.mu.Unlock()
	if c.tlsState == nil {
		state := c.Conn.(*tls.Conn).ConnectionState()
		c.tlsState = &state
	}
	return c.tlsState
}

type idleHTTPContextKey struct{}

func idleHTTPContext(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, idleHTTPContextKey{}, idleHTTPConnection(conn))
}
func idleRequestConnection(ctx context.Context) *idleConnection {
	c, _ := ctx.Value(idleHTTPContextKey{}).(*idleConnection)
	return c
}
func idleHTTPState(conn net.Conn, state http.ConnState) {
	c := idleHTTPConnection(conn)
	if c == nil {
		return
	}
	p := c.policy
	p.mu.Lock()
	defer p.mu.Unlock()
	if c.closed {
		return
	}
	switch state {
	case http.StateActive:
		// A quiet client while its target computes a response is not an inactive
		// incomplete request. Backend deadlines must be allowed to produce HTTP504.
		c.active = true
		c.bodyTimedOut = false
		c.timer.Stop()
	case http.StateIdle, http.StateHijacked:
		c.active = false
		c.input = false
		c.reading = false
		_ = c.Conn.SetReadDeadline(time.Time{})
		c.last = time.Now()
		c.timer.Reset(p.timeout)
	}
}

type idleRequestBody struct {
	io.ReadCloser
	connection *idleConnection
}

func (b *idleRequestBody) Read(buffer []byte) (int, error) {
	c := b.connection
	p := c.policy
	p.mu.Lock()
	c.reading = true
	c.readAt = time.Now()
	_ = c.Conn.SetReadDeadline(c.readAt.Add(p.timeout))
	p.mu.Unlock()
	n, err := b.ReadCloser.Read(buffer)
	p.mu.Lock()
	c.reading = false
	// Preserve a failed read deadline while net/http closes or drains the
	// incomplete body; clearing it would make that cleanup block indefinitely.
	if err == nil || errors.Is(err, io.EOF) {
		_ = c.Conn.SetReadDeadline(time.Time{})
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		c.bodyTimedOut = true
	}
	p.mu.Unlock()
	return n, err
}
func (c *idleConnection) clientBodyTimeout() bool {
	c.policy.mu.Lock()
	defer c.policy.mu.Unlock()
	return c.bodyTimedOut
}
