package elbv2

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

const callbackTimeout = 3 * time.Second

type relayConfiguration struct {
	Epoch    string
	Revision uint64
	Address  string
	Ports    []int
	Enabled  bool
}

type relayReport struct {
	Boot     string
	Epoch    string
	Revision uint64
	Errors   map[int]string
}

type dialRequest struct {
	Network, Address string
	Timeout          time.Duration
}

type dialResult struct {
	Local, Remote, Error string
}

type callback struct {
	mu           sync.Mutex
	address      netip.Addr
	token, epoch string
	server       *http.Server
	listener     net.Listener
	closed       chan struct{}
	done         bool
	enabled      bool
	revision     uint64
	observed     bool
	changed      chan struct{}
	ports        map[int]*socketListener
	connections  map[*socketConn]struct{}
	reverse      chan *socketConn
	boot         string
	refresh      func()
}

func newCallback(listener net.Listener, address netip.Addr, token string) *callback {
	c := &callback{address: address, token: token, epoch: rand.Text(), listener: listener,
		closed: make(chan struct{}), changed: make(chan struct{}), ports: make(map[int]*socketListener),
		connections: make(map[*socketConn]struct{}), reverse: make(chan *socketConn, 16)}
	c.server = &http.Server{Handler: c, ReadHeaderTimeout: callbackTimeout, IdleTimeout: callbackTimeout, MaxHeaderBytes: 8192}
	go func() {
		if err := c.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.close()
		}
	}()
	return c
}

func (c *callback) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *callback) setEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enableLocked(enabled)
}

func (c *callback) enableLocked(enabled bool) {
	c.enabled = enabled
	c.revision++
	c.observed = false
	for _, listener := range c.ports {
		listener.ready = false
	}
	if !enabled {
		for conn := range c.connections {
			conn.Conn.Close()
		}
		clear(c.connections)
	draining:
		for {
			select {
			case conn := <-c.reverse:
				conn.Conn.Close()
			default:
				break draining
			}
		}
	}
	c.notifyLocked()
}

func (c *callback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	address, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || address.Unmap() != c.address || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+c.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/config" {
		var report relayReport
		if err := json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&report); err != nil {
			http.Error(w, "invalid readiness report", http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.done {
			http.Error(w, "detached", http.StatusServiceUnavailable)
			return
		}
		if report.Boot == "" {
			http.Error(w, "missing native relay identity", http.StatusBadRequest)
			return
		}
		if report.Boot != c.boot {
			c.boot = report.Boot
			if c.refresh != nil {
				c.enableLocked(false)
				go c.refresh()
			}
		}
		if report.Epoch == c.epoch && report.Revision == c.revision {
			c.observed = true
			for port, listener := range c.ports {
				message, reported := report.Errors[port]
				listener.ready = c.enabled && reported && message == ""
				listener.failure = message
			}
			c.notifyLocked()
		}
		config := relayConfiguration{Epoch: c.epoch, Revision: c.revision, Address: c.address.String(), Enabled: c.enabled}
		if c.enabled {
			for port := range c.ports {
				config.Ports = append(config.Ports, port)
			}
			sort.Ints(config.Ports)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
		return
	}
	if r.Method != http.MethodConnect || (r.URL.Path != "/ingress" && r.URL.Path != "/dial") {
		http.NotFound(w, r)
		return
	}
	c.mu.Lock()
	if c.done || !c.enabled {
		c.mu.Unlock()
		http.Error(w, "node unavailable", http.StatusServiceUnavailable)
		return
	}
	var target *socketListener
	var remote, local *net.TCPAddr
	if r.URL.Path == "/ingress" {
		port, err := strconv.Atoi(r.Header.Get("X-Stackd-Port"))
		remote, parseErr = net.ResolveTCPAddr("tcp4", r.Header.Get("X-Stackd-Source"))
		target = c.ports[port]
		if err != nil || parseErr != nil || remote.IP.To4() == nil || remote.Port < 1 || target == nil || !target.ready {
			c.mu.Unlock()
			http.Error(w, "listener unavailable", http.StatusServiceUnavailable)
			return
		}
		local = &net.TCPAddr{IP: net.IP(c.address.AsSlice()), Port: port}
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		c.mu.Unlock()
		http.Error(w, "raw sockets unavailable", http.StatusInternalServerError)
		return
	}
	raw, buffer, err := hijacker.Hijack()
	if err != nil {
		c.mu.Unlock()
		return
	}
	conn := &socketConn{Conn: raw, reader: buffer.Reader, owner: c, local: local, remote: remote}
	c.connections[conn] = struct{}{}
	c.mu.Unlock()
	raw.SetDeadline(time.Now().Add(callbackTimeout))
	_, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err == nil {
		err = buffer.Flush()
	}
	raw.SetDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return
	}
	if target != nil {
		select {
		case target.incoming <- conn:
		case <-target.closed:
			conn.Close()
		case <-c.closed:
			conn.Close()
		}
		return
	}
	select {
	case c.reverse <- conn:
	case <-c.closed:
		conn.Close()
	}
}

func (c *callback) await(ctx context.Context, listener *socketListener) error {
	for {
		c.mu.Lock()
		if c.done {
			c.mu.Unlock()
			return net.ErrClosed
		}
		if listener != nil && listener.failure != "" {
			err := fmt.Errorf("native listener: %s", listener.failure)
			c.mu.Unlock()
			return err
		}
		ready := c.observed && c.enabled
		if listener != nil {
			ready = ready && listener.ready
		}
		changed := c.changed
		c.mu.Unlock()
		if ready {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *callback) listen(ctx context.Context, port int) (net.Listener, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("ALB listener port must be between 1 and 65535")
	}
	c.mu.Lock()
	if c.done || !c.enabled {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if c.ports[port] != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("ALB port %d is already listening", port)
	}
	listener := &socketListener{owner: c, port: port, incoming: make(chan net.Conn), closed: make(chan struct{})}
	c.ports[port] = listener
	c.revision++
	c.observed = false
	c.notifyLocked()
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.await(ctx, listener); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func (c *callback) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("ALB native sockets require tcp or tcp4, got %q", network)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if err := c.await(ctx, nil); err != nil {
			return nil, err
		}
		var conn *socketConn
		select {
		case conn = <-c.reverse:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.closed:
			return nil, net.ErrClosed
		}
		deadline, _ := ctx.Deadline()
		conn.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		request := dialRequest{Network: "tcp4", Address: address, Timeout: time.Until(deadline)}
		err := json.NewEncoder(conn).Encode(request)
		var result dialResult
		if err == nil {
			line, readErr := readControlLine(conn.reader)
			err = readErr
			if err == nil {
				err = json.Unmarshal(line, &result)
			}
		}
		if !stop() && err == nil {
			err = ctx.Err()
		}
		if err != nil {
			conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// Idle pool sockets from a previous relay process can have reached
			// EOF before consumption. They never supplied a native dial result.
			continue
		}
		if err == nil && result.Error != "" {
			err = errors.New(result.Error)
		}
		if err == nil {
			conn.local, err = net.ResolveTCPAddr("tcp4", result.Local)
		}
		if err == nil {
			conn.remote, err = net.ResolveTCPAddr("tcp4", result.Remote)
		}
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("ALB native dial %s: %w", address, err)
		}
		conn.SetDeadline(time.Time{})
		return conn, nil
	}
}

func (c *callback) close() error {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return nil
	}
	c.done = true
	close(c.closed)
	for _, listener := range c.ports {
		close(listener.closed)
	}
	clear(c.ports)
	for conn := range c.connections {
		conn.Conn.Close()
	}
	clear(c.connections)
	c.notifyLocked()
	c.mu.Unlock()
	return c.server.Close()
}

type socketListener struct {
	owner    *callback
	port     int
	incoming chan net.Conn
	closed   chan struct{}
	ready    bool
	failure  string
}

func (l *socketListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.incoming:
		return conn, nil
	}
}

func (l *socketListener) Close() error {
	c := l.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ports[l.port] == l {
		delete(c.ports, l.port)
		close(l.closed)
		c.revision++
		c.observed = false
		c.notifyLocked()
	}
	return nil
}

func (l *socketListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IP(l.owner.address.AsSlice()), Port: l.port}
}

type socketConn struct {
	net.Conn
	reader        *bufio.Reader
	owner         *callback
	local, remote *net.TCPAddr
}

func (c *socketConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *socketConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Conn.LocalAddr()
}
func (c *socketConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}
func (c *socketConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Conn.Close()
}
func (c *socketConn) Close() error {
	if c.owner != nil {
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
	}
	return c.Conn.Close()
}

func readControlLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("read native socket control: %w", err)
	}
	return line, nil
}
