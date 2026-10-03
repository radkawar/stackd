package lambda

import (
	"context"
	"net"
	"time"

	"stackd/compute/network"
)

// A mapping's running consumer and admission preflight may share its ENI and
// namespace, but never each other's socket lifetime. Policy remains mapping-wide.
type sourceNetworkLease struct {
	attachment *sourceNetworkAttachment
	closed     bool // guarded by attachment.mu
}

func (a *sourceNetworkAttachment) lease() *sourceNetworkLease {
	a.mu.Lock()
	defer a.mu.Unlock()
	lease := &sourceNetworkLease{attachment: a}
	a.leases[lease] = struct{}{}
	return lease
}

func (l *sourceNetworkLease) DialContext(ctx context.Context, kind, address string) (net.Conn, error) {
	return l.attachment.dialContext(ctx, kind, address, l)
}

func (l *sourceNetworkLease) SetPolicy(ctx context.Context, spec network.Specification) error {
	a := l.attachment
	a.mu.Lock()
	closed := l.closed || a.closed
	a.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return a.SetPolicy(ctx, spec)
}

func (l *sourceNetworkLease) Revoke() {
	a := l.attachment
	a.mu.Lock()
	defer a.mu.Unlock()
	if !l.closed && !a.closed {
		a.revokeLocked()
	}
}

func (l *sourceNetworkLease) Close() error {
	a := l.attachment
	r := a.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	a.mu.Lock()
	if l.closed {
		a.mu.Unlock()
		return nil
	}
	l.closed = true
	delete(a.leases, l)
	for conn := range a.connections {
		if conn.lease == l {
			conn.abort()
			delete(a.connections, conn)
		}
	}
	if a.closed || len(a.leases) != 0 {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()
	delete(r.active, a.mapping)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return r.release(ctx, a.mapping)
}
