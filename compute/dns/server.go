// Package dns serves authoritative owner-provided records over UDP and TCP.
// Resource state stays with the service owner; this endpoint has no record store,
// recursive forwarder, host resolver dependency, or host configuration effects.
package dns

import (
	"context"
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
}

// Listen binds the same explicit IPv4 host:port for UDP and TCP. Port zero
// selects a shared ephemeral port. No default listener or resolver is installed.
func Listen(address string) (*Server, error) {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	if !endpoint.Addr().Is4() {
		return nil, errors.New("DNS requires an explicit IPv4 listen address")
	}
	tcp, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(endpoint))
	if err != nil {
		return nil, err
	}
	bound := tcp.Addr().(*net.TCPAddr)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bound.IP, Port: bound.Port})
	if err != nil {
		tcp.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{udp: udp, tcp: tcp, ctx: ctx, cancel: cancel, connections: map[net.Conn]struct{}{}}
	for range 8 {
		s.workers.Add(1)
		go s.serveUDP()
	}
	s.workers.Add(1)
	go s.serveTCP()
	return s, nil
}

func (s *Server) Address() string { return s.tcp.Addr().String() }

// Register attaches a service authority, not copied resource records. The
// returned release detaches only this registration and waits for its readers.
func (s *Server) Register(resolver Resolver) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || resolver == nil {
		return nil, errors.New("DNS endpoint is closed or resolver is absent")
	}
	entry := &registration{resolver: resolver}
	s.owners = append(s.owners, entry)
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, owner := range s.owners {
			if owner == entry {
				s.owners = append(s.owners[:i], s.owners[i+1:]...)
				return
			}
		}
	}, nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	err := errors.Join(s.udp.Close(), s.tcp.Close())
	for connection := range s.connections {
		_ = connection.Close()
	}
	s.mu.Unlock()
	s.workers.Wait()
	return err
}

func (s *Server) serveUDP() {
	defer s.workers.Done()
	buffer := make([]byte, 65535)
	for {
		n, peer, err := s.udp.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		response := s.answer(buffer[:n], true)
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

func (s *Server) serveConnection(connection net.Conn) {
	defer s.workers.Done()
	defer func() {
		_ = connection.Close()
		s.mu.Lock()
		delete(s.connections, connection)
		s.mu.Unlock()
	}()
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
		response := s.answer(buffer[:n], false)
		if len(response) == 0 {
			return
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(response)))
		if _, err := connection.Write(length[:]); err != nil {
			return
		}
		if _, err := connection.Write(response); err != nil {
			return
		}
	}
}

func (s *Server) answer(packet []byte, udp bool) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil || header.Response {
		return nil
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: header.ID, Response: true, OpCode: header.OpCode, RecursionDesired: header.RecursionDesired}}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		response.RCode = dnsmessage.RCodeFormatError
	} else if header.OpCode != 0 {
		response.RCode = dnsmessage.RCodeNotImplemented
	} else {
		response.Questions = questions
		response.RCode = dnsmessage.RCodeRefused
		if questions[0].Class == dnsmessage.ClassINET {
			ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
			s.mu.RLock()
			for _, owner := range s.owners {
				result, lookupErr := owner.resolver.LookupDNS(ctx, questions[0])
				if lookupErr != nil {
					response.RCode = dnsmessage.RCodeServerFailure
					break
				}
				if !result.Authoritative && !result.Referral {
					continue
				}
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
			cancel()
		}
	}
	encoded, err := response.Pack()
	if err != nil {
		return nil
	}
	// A 512-byte UDP ceiling works with both classic and EDNS clients; larger
	// answers set TC and are available in full over the same TCP endpoint.
	if udp && len(encoded) > 512 {
		response.Truncated = true
		response.Answers = nil
		response.Authorities = nil
		response.Additionals = nil
		encoded, _ = response.Pack()
	}
	return encoded
}
