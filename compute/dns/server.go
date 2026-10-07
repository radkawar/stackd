// Package dns serves owner-provided records and explicitly configured upstreams
// over UDP and TCP. Resource state stays with its service owner; this endpoint
// has no record store, host resolver dependency, or host configuration effects.
package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Result distinguishes an unknown zone from an absent name in an owned zone.
// Existing names with no records of the requested type return Exists=true.
type Result struct {
	Authoritative bool
	// Referral handles a delegated subzone without claiming authority for its answer.
	Referral    bool
	Exists      bool
	Answers     []dnsmessage.Resource
	Authorities []dnsmessage.Resource
	Additionals []dnsmessage.Resource
}

type Resolver interface {
	LookupDNS(context.Context, dnsmessage.Question) (Result, error)
}

// Config installs no upstream by default. When forwarding is configured, an
// empty AllowedClients permits only loopback peers. Forwarding requires RD.
type Config struct {
	Address        string
	Upstreams      []netip.AddrPort
	AllowedClients []netip.Prefix
}

type registration struct{ resolver Resolver }

type Server struct {
	udp         *net.UDPConn
	tcp         *net.TCPListener
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	owners      []*registration
	connections map[net.Conn]struct{}
	closed      bool
	workers     sync.WaitGroup
	closeOnce   sync.Once
	closeDone   chan struct{}
	closeErr    error
	upstreams   []netip.AddrPort
	clients     []netip.Prefix
	loopToken   [16]byte
}

// Listen binds the same explicit IPv4 host:port for UDP and TCP. Port zero
// selects a shared ephemeral port. No default listener or resolver is installed.
func Listen(config Config) (*Server, error) {
	endpoint, err := netip.ParseAddrPort(config.Address)
	if err != nil {
		return nil, err
	}
	if !endpoint.Addr().Is4() || endpoint.Addr().IsMulticast() {
		return nil, errors.New("DNS requires an explicit IPv4 listen address")
	}
	clients, err := clientPrefixes(config.AllowedClients)
	if err != nil {
		return nil, err
	}
	upstreams := make([]netip.AddrPort, len(config.Upstreams))
	for i, upstream := range config.Upstreams {
		if !upstream.IsValid() || upstream.Port() == 0 || !usableAddress(upstream.Addr()) {
			return nil, errors.New("DNS upstream requires an explicit unicast address and nonzero port")
		}
		upstreams[i] = netip.AddrPortFrom(upstream.Addr().Unmap(), upstream.Port())
	}
	var loopToken [16]byte
	if len(upstreams) != 0 {
		if _, err := rand.Read(loopToken[:]); err != nil {
			return nil, err
		}
	}
	tcp, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(endpoint))
	if err != nil {
		return nil, err
	}
	bound := tcp.Addr().(*net.TCPAddr)
	if err := rejectSelfUpstreams(bound.AddrPort(), upstreams); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bound.IP, Port: bound.Port})
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		udp: udp, tcp: tcp, ctx: ctx, cancel: cancel,
		connections: map[net.Conn]struct{}{}, closeDone: make(chan struct{}),
		upstreams: upstreams, clients: clients, loopToken: loopToken,
	}
	for range 8 {
		s.workers.Add(1)
		go s.serveUDP()
	}
	s.workers.Add(1)
	go s.serveTCP()
	return s, nil
}

func (s *Server) Address() string { return s.tcp.Addr().String() }

// Register attaches a service authority, not copied resource records. Native
// owners always precede NewNamespace/NewRedirect fallbacks, even when registered
// later. The returned release detaches only this registration and waits for its
// readers, so the owner can safely close its retained state afterwards.
func (s *Server) Register(resolver Resolver) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || resolver == nil {
		return nil, errors.New("DNS endpoint is closed or resolver is absent")
	}
	entry := &registration{resolver: resolver}
	index := len(s.owners)
	if _, fallback := resolver.(*namespace); !fallback {
		for i, owner := range s.owners {
			if _, fallback := owner.resolver.(*namespace); fallback {
				index = i
				break
			}
		}
	}
	s.owners = append(s.owners, nil)
	copy(s.owners[index+1:], s.owners[index:])
	s.owners[index] = entry
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, owner := range s.owners {
			if owner == entry {
				copy(s.owners[i:], s.owners[i+1:])
				s.owners[len(s.owners)-1] = nil
				s.owners = s.owners[:len(s.owners)-1]
				return
			}
		}
	}, nil
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		// Cancel before waiting for owner readers: a resolver may itself be
		// waiting for this context before it releases its registration read.
		s.cancel()
		s.mu.Lock()
		s.closed = true
		s.closeErr = errors.Join(s.udp.Close(), s.tcp.Close())
		for connection := range s.connections {
			_ = connection.Close()
		}
		s.mu.Unlock()
		s.workers.Wait()
		close(s.closeDone)
	})
	<-s.closeDone
	return s.closeErr
}

func (s *Server) serveUDP() {
	defer s.workers.Done()
	buffer := make([]byte, 65535)
	for {
		n, peer, err := s.udp.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		response := s.answer(withPeerAddress(s.ctx, peer.Addr()), buffer[:n], true)
		if len(response) != 0 {
			_, _ = s.udp.WriteToUDPAddrPort(response, peer)
		}
	}
}

func (s *Server) serveTCP() {
	defer s.workers.Done()
	for {
		connection, err := s.tcp.AcceptTCP()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed || len(s.connections) >= 128 {
			s.mu.Unlock()
			_ = connection.Close()
			continue
		}
		s.connections[connection] = struct{}{}
		s.workers.Add(1)
		s.mu.Unlock()
		go s.serveConnection(connection)
	}
}

func (s *Server) serveConnection(connection *net.TCPConn) {
	defer s.workers.Done()
	defer func() {
		_ = connection.Close()
		s.mu.Lock()
		delete(s.connections, connection)
		s.mu.Unlock()
	}()
	ctx := withPeerAddress(s.ctx, connection.RemoteAddr().(*net.TCPAddr).AddrPort().Addr())
	var length [2]byte
	buffer := make([]byte, 65535)
	for {
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(connection, buffer[:n]); err != nil {
			return
		}
		response := s.answer(ctx, buffer[:n], false)
		if len(response) == 0 || writeTCPMessage(connection, response) != nil {
			return
		}
	}
}

func (s *Server) answer(peerCtx context.Context, packet []byte, udp bool) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil || header.Response {
		return nil
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: header.ID, Response: true, OpCode: header.OpCode, RecursionDesired: header.RecursionDesired}}
	var request dnsmessage.Message
	if err := request.Unpack(packet); err != nil || len(request.Questions) != 1 {
		response.RCode = dnsmessage.RCodeFormatError
	} else if header.OpCode != 0 {
		response.RCode = dnsmessage.RCodeNotImplemented
	} else {
		response.Questions = request.Questions
		response.RCode = dnsmessage.RCodeRefused
		peer, ok := PeerAddress(peerCtx)
		canForward := len(s.upstreams) != 0 && ok && allowsClient(s.clients, peer, true)
		response.RecursionAvailable = canForward
		if request.Questions[0].Class == dnsmessage.ClassINET {
			ctx, cancel := context.WithTimeout(peerCtx, 3*time.Second)
			s.mu.RLock()
			owned := false
			for _, owner := range s.owners {
				result, lookupErr := owner.resolver.LookupDNS(ctx, request.Questions[0])
				if lookupErr != nil {
					response.Authoritative = result.Authoritative
					response.RCode = dnsmessage.RCodeServerFailure
					owned = true
					break
				}
				if !result.Authoritative && !result.Referral {
					continue
				}
				owned = true
				response.Authoritative = result.Authoritative
				response.RCode = dnsmessage.RCodeSuccess
				if !result.Exists && !result.Referral {
					response.RCode = dnsmessage.RCodeNameError
				}
				response.Answers = result.Answers
				response.Authorities = result.Authorities
				response.Additionals = result.Additionals
				break
			}
			s.mu.RUnlock()
			if !owned && canForward && header.RecursionDesired {
				forwarded, err := s.forward(ctx, request, !udp)
				if err != nil {
					response.RCode = dnsmessage.RCodeServerFailure
				} else {
					response = forwarded
					response.ID = header.ID
					response.RecursionDesired = header.RecursionDesired
					response.RecursionAvailable = true
				}
			}
			cancel()
		}
	}
	encoded, err := response.Pack()
	if err != nil || !udp && len(encoded) > 65535 {
		// Invalid owner/upstream data is an error response, not a hung client.
		response.RCode = dnsmessage.RCodeServerFailure
		response.Answers, response.Authorities, response.Additionals = nil, nil, nil
		encoded, err = response.Pack()
		if err != nil {
			return nil
		}
	}
	// The conservative classic UDP ceiling applies even to EDNS clients.
	// Complete answers remain available over the same TCP endpoint.
	if udp && len(encoded) > 512 {
		response.Truncated = true
		response.Answers, response.Authorities, response.Additionals = nil, nil, nil
		encoded, _ = response.Pack()
	}
	return encoded
}
