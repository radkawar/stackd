package ec2

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

type metadataConnectionKey struct{}

// The response writer changes the actual native socket's IPv4 TTL. Token
// responses close their connection, so a subsequent metadata request cannot
// inherit the token's hop-limit through HTTP keepalive.
type metadataWriter struct {
	http.ResponseWriter
	connection *net.TCPConn
	wrote      bool
}

func (w *metadataWriter) WriteHeader(status int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}
func (w *metadataWriter) Write(data []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(data)
}
func (w *metadataWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *metadataWriter) SetHopLimit(limit int) error {
	if limit < 1 || limit > 255 || w.wrote {
		return errors.New("metadata hop limit must be set before writing the response and be between 1 and 255")
	}
	if w.connection == nil {
		return errors.New("native IPv4 metadata connection unavailable")
	}
	connection, err := w.connection.SyscallConn()
	if err != nil {
		return err
	}
	var optionError error
	if err := connection.Control(func(fd uintptr) { optionError = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, limit) }); err != nil {
		return err
	}
	if optionError != nil {
		return optionError
	}
	w.Header().Set("Connection", "close")
	return nil
}

func (a *guestAttachment) prepareMetadata(ctx context.Context, handler http.Handler) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", net.JoinHostPort(a.spec.Gateway.String(), "0"))
	if err != nil {
		return err
	}
	a.callback = listener.Addr().String()
	address := a.spec.Address
	a.server = &http.Server{
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			return context.WithValue(ctx, metadataConnectionKey{}, connection)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			source, parseErr := netip.ParseAddr(host)
			if err != nil || parseErr != nil || source.Unmap() != address {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			connection, _ := r.Context().Value(metadataConnectionKey{}).(*net.TCPConn)
			handler.ServeHTTP(&metadataWriter{ResponseWriter: w, connection: connection}, r)
		}),
	}
	if err := a.installMetadataRules(ctx); err != nil {
		listener.Close()
		return err
	}
	go func() { _ = a.server.Serve(listener) }()
	return nil
}

func metadataTable(arn string) string { return "stackd_imds_" + identifier(arn) }

func (a *guestAttachment) installMetadataRules(ctx context.Context) error {
	host, port, err := net.SplitHostPort(a.callback)
	if err != nil || host != a.spec.Gateway.String() {
		return errors.New("native metadata callback is not bound to the VPC gateway")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("invalid native metadata callback port")
	}
	// Packet marks are native routing plumbing, not a stored bearer credential.
	// Exact TAP, MAC, source, bridge and original IMDS tuple also constrain DNAT.
	bytes, err := hex.DecodeString(identifier(a.arn)[:8])
	if err != nil {
		return err
	}
	mark := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	if mark == 0 {
		mark = 1
	}
	name := metadataTable(a.arn)
	rules := fmt.Sprintf(`destroy table bridge %s
destroy table ip %s
table bridge %s {
 chain metadata_mark { type filter hook prerouting priority -450; policy accept;
  iifname %q ether saddr %s ether type ip ip saddr %s ip daddr 169.254.169.254 tcp dport 80 meta mark set %d
 }
}
table ip %s {
 chain metadata_nat { type nat hook prerouting priority -100; policy accept;
  iifname %q ether saddr %s ip saddr %s ip daddr 169.254.169.254 tcp dport 80 meta mark %d dnat to %s:%d
 }
 chain metadata_guard { type filter hook input priority -200; policy accept;
  iifname %q ip saddr %s ip daddr %s tcp dport %d meta mark %d ct status dnat accept
  ip daddr %s tcp dport %d counter drop
 }
}
`, name, name, name, a.tap, a.spec.MAC, a.spec.Address, mark, name, a.bridge.Device, a.spec.MAC, a.spec.Address, mark, host, portNumber, a.bridge.Device, a.spec.Address, host, portNumber, mark, host, portNumber)
	_, err = a.manager.helper(ctx, a.arn, []string{"/bin/sh", "-ec", "printf '%s' \"$RULES\" | nft -f -"}, []string{"RULES=" + rules})
	return err
}

func (m *GuestNetworkManager) removeMetadataRules(ctx context.Context, arn string) error {
	name := metadataTable(arn)
	rules := "destroy table bridge " + name + "\ndestroy table ip " + name + "\n"
	_, err := m.helper(ctx, arn, []string{"/bin/sh", "-ec", "printf '%s' \"$RULES\" | nft -f -"}, []string{"RULES=" + rules})
	return err
}
