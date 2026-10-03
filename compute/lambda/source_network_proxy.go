package lambda

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"stackd/compute/docker"
)

// The Engine upgrade carries bytes, not broker connections: every connect(2)
// occurs inside the mapping's native VPC namespace. The unprivileged helper has
// no host network or Docker socket and cannot alter its external packet policy.
const sourceSocketProxy = `
import os, select, socket, sys
host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
connection = None
try:
    for family, kind, proto, canon, address in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        candidate = socket.socket(family, kind, proto)
        candidate.settimeout(timeout)
        try:
            candidate.connect(address)
            connection = candidate
            break
        except OSError:
            candidate.close()
    if connection is None:
        raise OSError("source address is unreachable through its VPC attachment")
    os.write(1, b'\x00')
    while True:
        ready, _, _ = select.select([0, connection], [], [])
        if 0 in ready:
            data = os.read(0, 65536)
            if not data:
                break
            connection.sendall(data)
        if connection in ready:
            data = connection.recv(65536)
            if not data:
                break
            view = memoryview(data)
            while view:
                view = view[os.write(1, view):]
except OSError as error:
    if connection is None:
        os.write(1, b'\x01' + str(error).encode()[:1024])
finally:
    if connection is not None:
        connection.close()
`

type sourceProxyConn struct {
	net.Conn
	attachment *sourceNetworkAttachment
	lease      *sourceNetworkLease
	stream     io.ReadWriteCloser
	remote     net.Conn
	cancel     context.CancelFunc
	once       sync.Once
}

func (c *sourceProxyConn) abort() {
	c.once.Do(func() { c.cancel(); _ = c.stream.Close(); _ = c.remote.Close(); _ = c.Conn.Close() })
}
func (c *sourceProxyConn) Close() error {
	c.abort()
	c.attachment.mu.Lock()
	delete(c.attachment.connections, c)
	c.attachment.mu.Unlock()
	return nil
}

func (a *sourceNetworkAttachment) dialContext(ctx context.Context, kind, address string, lease *sourceNetworkLease) (net.Conn, error) {
	if kind != "tcp" && kind != "tcp4" {
		return nil, fmt.Errorf("lambda source namespace does not support %q sockets", kind)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid source TCP port")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified()) {
		return nil, errors.New("source VPC sockets require a reachable non-loopback IPv4 endpoint")
	}
	if host == "localhost" {
		return nil, errors.New("source VPC sockets cannot use host-local endpoints")
	}
	a.mu.Lock()
	closed := a.closed || lease.closed
	a.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	timeout := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	var exec struct {
		ID string `json:"Id"`
	}
	input := struct {
		AttachStdin, AttachStdout, AttachStderr bool
		Cmd                                     []string
	}{true, true, true, []string{"python3", "-u", "-c", sourceSocketProxy, host, portText, strconv.FormatFloat(timeout.Seconds(), 'f', 3, 64)}}
	if err := a.runtime.client.JSON(ctx, http.MethodPost, "/containers/"+a.runtime.container(a.mapping)+"/exec", input, &exec); err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, cancel)
	body, _ := json.Marshal(struct{ Detach, Tty bool }{})
	response, err := a.runtime.client.RequestHeaders(life, http.MethodPost, "/exec/"+exec.ID+"/start", bytes.NewReader(body), "application/json", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"tcp"}})
	if err != nil {
		stop()
		cancel()
		return nil, err
	}
	stream, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		stop()
		cancel()
		_ = response.Body.Close()
		return nil, errors.New("docker source socket requires a duplex Engine upgrade")
	}
	local, remote := net.Pipe()
	conn := &sourceProxyConn{Conn: local, attachment: a, lease: lease, stream: stream, remote: remote, cancel: cancel}
	a.mu.Lock()
	if a.closed || lease.closed {
		a.mu.Unlock()
		stop()
		conn.abort()
		return nil, net.ErrClosed
	}
	a.connections[conn] = struct{}{}
	a.mu.Unlock()
	go func() { _, _ = io.Copy(stream, remote); _ = conn.Close() }()
	go func() { _ = docker.CopyStream(remote, io.Discard, stream); _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = local.SetReadDeadline(deadline)
	} else {
		_ = local.SetReadDeadline(time.Now().Add(timeout))
	}
	var status [1]byte
	_, err = io.ReadFull(local, status[:])
	if err == nil && status[0] != 0 {
		message, _ := io.ReadAll(io.LimitReader(local, 1024))
		err = fmt.Errorf("connect source through VPC: %s", message)
	}
	stop()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = local.SetReadDeadline(time.Time{})
	return conn, nil
}
