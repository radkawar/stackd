package elbv2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// RunRelay runs inside the owned node network namespace. It opens only native
// TCP sockets; the parent owns every HTTP/TLS listener and routing decision.
// Callback loss closes public listeners and active streams. The retained
// callback is retried without replacing the namespace or changing its identity.
func RunRelay(ctx context.Context, callbackAddress, token string) error {
	endpoint, err := netip.ParseAddrPort(callbackAddress)
	if err != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 || token == "" {
		return errors.New("ALB relay requires an IPv4 callback and retained token")
	}
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: callbackTimeout}).DialContext, MaxIdleConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: callbackTimeout}
	r := &nativeRelay{callback: callbackAddress, token: token, ports: make(map[int]net.Listener)}
	defer r.reset()
	report := relayReport{Boot: rand.Text()}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		payload, err := json.Marshal(report)
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+callbackAddress+"/config", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		var config relayConfiguration
		if err == nil {
			if response.StatusCode != http.StatusOK {
				err = fmt.Errorf("callback HTTP %d", response.StatusCode)
			} else {
				err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&config)
			}
			response.Body.Close()
		}
		if err != nil {
			r.reset()
			report = relayReport{Boot: report.Boot}
		} else {
			next := r.configure(ctx, config)
			next.Boot = report.Boot
			report = next
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type nativeRelay struct {
	callback, token string
	epoch, address  string
	ports           map[int]net.Listener
	session         context.Context
	cancel          context.CancelFunc
}

func (r *nativeRelay) reset() {
	if r.cancel != nil {
		r.cancel()
	}
	for _, listener := range r.ports {
		listener.Close()
	}
	clear(r.ports)
	r.cancel = nil
	r.epoch = ""
}

func (r *nativeRelay) configure(ctx context.Context, config relayConfiguration) relayReport {
	report := relayReport{Epoch: config.Epoch, Revision: config.Revision, Errors: make(map[int]string)}
	address, err := netip.ParseAddr(config.Address)
	if !config.Enabled || err != nil || !address.Is4() {
		r.reset()
		return report
	}
	if r.cancel == nil || r.epoch != config.Epoch || r.address != config.Address {
		r.reset()
		r.epoch, r.address = config.Epoch, config.Address
		r.session, r.cancel = context.WithCancel(ctx)
		for range 16 {
			go r.reverse(r.session, address)
		}
	}
	wanted := make(map[int]bool, len(config.Ports))
	for _, port := range config.Ports {
		wanted[port] = true
	}
	for port, listener := range r.ports {
		if !wanted[port] {
			listener.Close()
			delete(r.ports, port)
		}
	}
	for _, port := range config.Ports {
		if port < 1 || port > 65535 {
			report.Errors[port] = "invalid native listener port"
			continue
		}
		if r.ports[port] == nil {
			listener, err := (&net.ListenConfig{}).Listen(r.session, "tcp4", net.JoinHostPort(config.Address, strconv.Itoa(port)))
			if err != nil {
				report.Errors[port] = err.Error()
				continue
			}
			r.ports[port] = listener
			go r.ingress(r.session, listener, port)
		}
		report.Errors[port] = ""
	}
	return report
}

func (r *nativeRelay) connect(ctx context.Context, path string, headers http.Header) (*socketConn, error) {
	raw, err := (&net.Dialer{Timeout: callbackTimeout}).DialContext(ctx, "tcp4", r.callback)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(callbackTimeout))
	request, err := http.NewRequest(http.MethodConnect, "http://"+r.callback+path, nil)
	if err != nil {
		raw.Close()
		return nil, err
	}
	request.Header = headers
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("Authorization", "Bearer "+r.token)
	// CONNECT uses a path, not an authority: this is a private callback protocol.
	_, err = fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", path, r.callback)
	if err == nil {
		err = request.Header.Write(raw)
	}
	if err == nil {
		_, err = io.WriteString(raw, "\r\n")
	}
	reader := bufio.NewReader(raw)
	var response *http.Response
	if err == nil {
		response, err = http.ReadResponse(reader, request)
	}
	if err == nil && response.StatusCode != http.StatusOK {
		err = fmt.Errorf("callback CONNECT HTTP %d", response.StatusCode)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return &socketConn{Conn: raw, reader: reader}, nil
}

func (r *nativeRelay) ingress(ctx context.Context, listener net.Listener, port int) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			header := http.Header{"X-Stackd-Port": []string{strconv.Itoa(port)}, "X-Stackd-Source": []string{conn.RemoteAddr().String()}}
			tunnel, err := r.connect(ctx, "/ingress", header)
			if err != nil {
				return
			}
			defer tunnel.Close()
			relaySockets(ctx, conn, tunnel)
		}()
	}
}

func (r *nativeRelay) reverse(ctx context.Context, address netip.Addr) {
	for ctx.Err() == nil {
		conn, err := r.connect(ctx, "/dial", nil)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		line, err := readControlLine(conn.reader)
		var request dialRequest
		if err == nil {
			err = json.Unmarshal(line, &request)
		}
		stop()
		if err != nil {
			conn.Close()
			continue
		}
		// Replenish this pool slot before servicing the real socket. The number
		// of simultaneous target connections is not limited by idle pool size.
		go r.dial(ctx, address, conn, request)
	}
}

func (r *nativeRelay) dial(ctx context.Context, address netip.Addr, conn *socketConn, request dialRequest) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if request.Timeout <= 0 || request.Timeout > 30*time.Second {
		request.Timeout = 30 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	var target net.Conn
	var err error
	if request.Network != "tcp4" {
		err = errors.New("native relay only dials IPv4 TCP")
	} else {
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(address.AsSlice())}}
		target, err = dialer.DialContext(dialCtx, "tcp4", request.Address)
	}
	result := dialResult{}
	if err != nil {
		result.Error = err.Error()
	} else {
		defer target.Close()
		result.Local, result.Remote = target.LocalAddr().String(), target.RemoteAddr().String()
	}
	conn.SetWriteDeadline(time.Now().Add(callbackTimeout))
	if json.NewEncoder(conn).Encode(result) != nil || err != nil {
		return
	}
	conn.SetWriteDeadline(time.Time{})
	relaySockets(ctx, conn, target)
}

func relaySockets(ctx context.Context, left, right net.Conn) {
	stop := context.AfterFunc(ctx, func() { left.Close(); right.Close() })
	defer stop()
	var group sync.WaitGroup
	group.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer group.Done()
		if _, err := io.Copy(dst, src); err != nil {
			left.Close()
			right.Close()
			return
		}
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			closer.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go copyHalf(left, right)
	go copyHalf(right, left)
	group.Wait()
}
