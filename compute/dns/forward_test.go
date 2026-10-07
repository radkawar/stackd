package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type wireUpstream struct {
	address netip.AddrPort
	udp     atomic.Int64
	tcp     atomic.Int64
}

// This is a protocol peer, not a Resolver: requests and replies cross actual
// UDP/TCP sockets so forwarding, matching, ACLs and framing remain observable.
func newWireUpstream(t *testing.T, answer func(string, dnsmessage.Message) []dnsmessage.Message) *wireUpstream {
	t.Helper()
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tcp.Addr().(*net.TCPAddr).Port})
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	peer := &wireUpstream{address: tcp.Addr().(*net.TCPAddr).AddrPort()}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		buffer := make([]byte, 65535)
		for {
			n, remote, err := udp.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if err := request.Unpack(buffer[:n]); err != nil {
				t.Errorf("upstream UDP query: %v", err)
				continue
			}
			peer.udp.Add(1)
			for _, response := range answer("udp", request) {
				packet, err := response.Pack()
				if err != nil {
					t.Errorf("upstream UDP response: %v", err)
					continue
				}
				_, _ = udp.WriteToUDPAddrPort(packet, remote)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			connection, err := tcp.AcceptTCP()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
				var length [2]byte
				if _, err := io.ReadFull(connection, length[:]); err != nil {
					return
				}
				packet := make([]byte, int(binary.BigEndian.Uint16(length[:])))
				if _, err := io.ReadFull(connection, packet); err != nil {
					return
				}
				var request dnsmessage.Message
				if err := request.Unpack(packet); err != nil {
					t.Errorf("upstream TCP query: %v", err)
					return
				}
				peer.tcp.Add(1)
				for _, response := range answer("tcp", request) {
					packet, err := response.Pack()
					if err != nil {
						t.Errorf("upstream TCP response: %v", err)
						return
					}
					binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
					if _, err := connection.Write(append(length[:], packet...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = udp.Close()
		_ = tcp.Close()
		workers.Wait()
	})
	return peer
}

func upstreamAnswer(request dnsmessage.Message) dnsmessage.Message {
	question := request.Questions[0]
	return dnsmessage.Message{
		Header:    dnsmessage.Header{ID: request.ID, Response: true, RecursionDesired: request.RecursionDesired, RecursionAvailable: true},
		Questions: request.Questions,
		Answers:   []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 37}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 19}}}},
	}
}

func listenTestDNS(t *testing.T, config Config) *Server {
	t.Helper()
	server, err := Listen(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	return server
}

func wireExchange(network, address string, source netip.Addr, request dnsmessage.Message) (dnsmessage.Message, error) {
	var response dnsmessage.Message
	packet, err := request.Pack()
	if err != nil {
		return response, err
	}
	dialer := net.Dialer{Timeout: time.Second}
	if source.IsValid() {
		if network == "tcp" {
			dialer.LocalAddr = &net.TCPAddr{IP: net.IP(source.AsSlice())}
		} else {
			dialer.LocalAddr = &net.UDPAddr{IP: net.IP(source.AsSlice())}
		}
	}
	connection, err := dialer.Dial(network, address)
	if err != nil {
		return response, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
	var length [2]byte
	if network == "tcp" {
		binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
		packet = append(length[:], packet...)
	}
	if _, err := connection.Write(packet); err != nil {
		return response, err
	}
	buffer := make([]byte, 65535)
	var n int
	if network == "tcp" {
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return response, err
		}
		n = int(binary.BigEndian.Uint16(length[:]))
		_, err = io.ReadFull(connection, buffer[:n])
	} else {
		n, err = connection.Read(buffer)
	}
	if err != nil {
		return response, err
	}
	if err := response.Unpack(buffer[:n]); err != nil {
		return response, err
	}
	if !response.Response || response.ID != request.ID {
		return response, fmt.Errorf("response header does not match: %+v", response.Header)
	}
	return response, nil
}

func recursiveRequest(t *testing.T, name string) dnsmessage.Message {
	t.Helper()
	return dnsmessage.Message{Header: dnsmessage.Header{ID: 1987, RecursionDesired: true}, Questions: []dnsmessage.Question{dnsQuestion(t, name, dnsmessage.TypeA)}}
}

func queryWire(t *testing.T, server *Server, network string, request dnsmessage.Message) dnsmessage.Message {
	t.Helper()
	response, err := wireExchange(network, server.Address(), netip.Addr{}, request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestNativeOwnersPrecedeNamespacesAndNeverForwardOwnedResults(t *testing.T) {
	upstream := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
		return []dnsmessage.Message{upstreamAnswer(request)}
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
	fallback, err := NewNamespace("gateway.example", []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Register(fallback); err != nil {
		t.Fatal(err)
	}
	zone, _ := dnsmessage.NewName("gateway.example.")
	ns, _ := dnsmessage.NewName("ns.gateway.example.")
	soa := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: zone, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.SOAResource{NS: ns, MBox: ns, Serial: 3, MinTTL: 30}}
	peers := make(chan netip.Addr, 10)
	release, err := server.Register(resolverFunc(func(ctx context.Context, question dnsmessage.Question) (Result, error) {
		if peer, ok := PeerAddress(ctx); ok {
			peers <- peer
		}
		switch question.Name.String() {
		case "missing.gateway.example.":
			return Result{Authoritative: true, Authorities: []dnsmessage.Resource{soa}}, nil
		case "nodata.gateway.example.":
			return Result{Authoritative: true, Exists: true, Authorities: []dnsmessage.Resource{soa}}, nil
		case "delegated.gateway.example.":
			return Result{Referral: true, Authorities: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.NSResource{NS: ns}}}}, nil
		case "error.gateway.example.":
			return Result{Authoritative: true}, errors.New("owner unavailable")
		}
		return Result{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "tcp"} {
		for _, scenario := range []struct {
			name          string
			code          dnsmessage.RCode
			authoritative bool
			authorities   int
		}{
			{"missing", dnsmessage.RCodeNameError, true, 1},
			{"nodata", dnsmessage.RCodeSuccess, true, 1},
			{"delegated", dnsmessage.RCodeSuccess, false, 1},
			{"error", dnsmessage.RCodeServerFailure, true, 0},
		} {
			response := queryWire(t, server, network, recursiveRequest(t, scenario.name+".gateway.example."))
			if response.RCode != scenario.code || response.Authoritative != scenario.authoritative || len(response.Authorities) != scenario.authorities || len(response.Answers) != 0 {
				t.Fatalf("%s %s owned result: %+v", network, scenario.name, response)
			}
			select {
			case peer := <-peers:
				if peer != netip.MustParseAddr("127.0.0.1") {
					t.Fatalf("%s did not supply its real peer: %s", network, peer)
				}
			case <-time.After(time.Second):
				t.Fatalf("%s owner was not supplied a serving peer", network)
			}
		}
	}
	if upstream.udp.Load()+upstream.tcp.Load() != 0 {
		t.Fatal("owned negative, NODATA, referral or error escaped upstream")
	}
	release()
	response := queryWire(t, server, "tcp", recursiveRequest(t, "missing.gateway.example."))
	if !response.Authoritative || response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 || response.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{127, 0, 0, 1} {
		t.Fatalf("withdrawal did not expose live namespace fallback: %+v", response)
	}
}

func TestForwardingIsExplicitRestrictedAndRequiresRD(t *testing.T) {
	upstream := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
		return []dnsmessage.Message{upstreamAnswer(request)}
	})
	for _, scenario := range []struct {
		name   string
		config Config
	}{
		{"no-upstream", Config{Address: "127.0.0.1:0"}},
		{"denied-loopback", Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}, AllowedClients: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := listenTestDNS(t, scenario.config)
			if len(scenario.config.AllowedClients) != 0 {
				scenario.config.AllowedClients[0] = netip.MustParsePrefix("127.0.0.0/8")
			}
			for _, network := range []string{"udp", "tcp"} {
				response := queryWire(t, server, network, recursiveRequest(t, "foreign.example."))
				if response.RCode != dnsmessage.RCodeRefused || response.RecursionAvailable || response.Authoritative {
					t.Fatalf("unconfigured/disallowed recursion: %+v", response)
				}
			}
		})
	}
	if upstream.udp.Load()+upstream.tcp.Load() != 0 {
		t.Fatal("a disallowed client reached the selected upstream")
	}
	endpoints := []netip.AddrPort{upstream.address}
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: endpoints})
	endpoints[0] = netip.MustParseAddrPort("192.0.2.1:53")
	for _, network := range []string{"udp", "tcp"} {
		request := recursiveRequest(t, "foreign.example.")
		request.RecursionDesired = false
		response := queryWire(t, server, network, request)
		if response.RCode != dnsmessage.RCodeRefused || !response.RecursionAvailable {
			t.Fatalf("RD=false unexpectedly recursed: %+v", response)
		}
		request.RecursionDesired = true
		request.Questions[0].Class = dnsmessage.ClassCHAOS
		if response := queryWire(t, server, network, request); response.RCode != dnsmessage.RCodeRefused {
			t.Fatalf("non-IN question recursed: %+v", response)
		}
	}
	if upstream.udp.Load()+upstream.tcp.Load() != 0 {
		t.Fatal("nonrecursive or unsupported question reached upstream")
	}
	for _, network := range []string{"udp", "tcp"} {
		response := queryWire(t, server, network, recursiveRequest(t, "foreign.example."))
		if response.RCode != dnsmessage.RCodeSuccess || !response.RecursionAvailable || response.Authoritative || len(response.Answers) != 1 || response.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 19} {
			t.Fatalf("explicit upstream answer: %+v", response)
		}
	}
	if upstream.udp.Load() != 1 || upstream.tcp.Load() != 1 {
		t.Fatalf("transport was not preserved: UDP=%d TCP=%d", upstream.udp.Load(), upstream.tcp.Load())
	}
}

func TestUpstreamNegativesAndErrorsRetainAuthoritySections(t *testing.T) {
	zone, _ := dnsmessage.NewName("foreign.example.")
	ns, _ := dnsmessage.NewName("ns.foreign.example.")
	for _, scenario := range []struct {
		name          string
		code          dnsmessage.RCode
		authoritative bool
		typeCode      dnsmessage.Type
	}{
		{"nxdomain", dnsmessage.RCodeNameError, true, dnsmessage.TypeSOA},
		{"nodata", dnsmessage.RCodeSuccess, true, dnsmessage.TypeSOA},
		{"referral", dnsmessage.RCodeSuccess, false, dnsmessage.TypeNS},
		{"servfail", dnsmessage.RCodeServerFailure, false, 0},
		{"refused", dnsmessage.RCodeRefused, false, 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			upstream := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
				response := upstreamAnswer(request)
				response.Answers = nil
				response.RCode, response.Authoritative = scenario.code, scenario.authoritative
				switch scenario.typeCode {
				case dnsmessage.TypeSOA:
					response.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: zone, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 43}, Body: &dnsmessage.SOAResource{NS: ns, MBox: ns, Serial: 19, MinTTL: 43}}}
				case dnsmessage.TypeNS:
					response.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: zone, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 43}, Body: &dnsmessage.NSResource{NS: ns}}}
					response.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: ns, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 43}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 9}}}}
				}
				return []dnsmessage.Message{response}
			})
			server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
			for _, network := range []string{"udp", "tcp"} {
				response := queryWire(t, server, network, recursiveRequest(t, "missing.foreign.example."))
				if response.RCode != scenario.code || response.Authoritative != scenario.authoritative || len(response.Answers) != 0 || !response.RecursionAvailable {
					t.Fatalf("%s upstream semantics changed: %+v", network, response)
				}
				if scenario.typeCode != 0 && (len(response.Authorities) != 1 || response.Authorities[0].Header.Type != scenario.typeCode || response.Authorities[0].Header.TTL != 43) {
					t.Fatalf("%s lost negative/referral authority: %+v", network, response)
				}
				if scenario.typeCode == dnsmessage.TypeNS && len(response.Additionals) != 1 {
					t.Fatalf("%s lost referral glue: %+v", network, response)
				}
			}
		})
	}
}

func TestUDPRejectsUnmatchedDatagramsBeforeMatchingAnswer(t *testing.T) {
	upstream := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
		valid := upstreamAnswer(request)
		wrongID := upstreamAnswer(request)
		wrongID.ID++
		wrongQuestion := upstreamAnswer(request)
		wrongQuestion.Questions = append([]dnsmessage.Question(nil), request.Questions...)
		wrongQuestion.Questions[0].Type = dnsmessage.TypeAAAA
		wrongName := upstreamAnswer(request)
		wrongName.Questions = append([]dnsmessage.Question(nil), request.Questions...)
		wrongName.Questions[0].Name, _ = dnsmessage.NewName("K.foreign.example.")
		wrongOpcode := upstreamAnswer(request)
		wrongOpcode.OpCode = 2
		queryNotResponse := upstreamAnswer(request)
		queryNotResponse.Response = false
		valid.Questions = append([]dnsmessage.Question(nil), request.Questions...)
		valid.Questions[0].Name, _ = dnsmessage.NewName(strings.ToUpper(request.Questions[0].Name.String()))
		invalid := []dnsmessage.Message{wrongID, wrongQuestion, wrongName, wrongOpcode, queryNotResponse}
		for i := range invalid {
			invalid[i].Answers[0].Body = &dnsmessage.AResource{A: [4]byte{198, 51, 100, 99}}
		}
		return append(invalid, valid)
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
	response := queryWire(t, server, "udp", recursiveRequest(t, "k.foreign.example."))
	if response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 || response.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 19} {
		t.Fatalf("unmatched UDP packet satisfied query or case folding failed: %+v", response)
	}
	if upstream.udp.Load() != 1 || upstream.tcp.Load() != 0 {
		t.Fatal("matching UDP answer unexpectedly required another transport")
	}
}

func TestForwardedUDPTruncationFallsBackToTCPAndDownstreamTCPIsComplete(t *testing.T) {
	upstream := newWireUpstream(t, func(network string, request dnsmessage.Message) []dnsmessage.Message {
		response := upstreamAnswer(request)
		if network == "udp" {
			response.Truncated, response.Answers = true, nil
		} else {
			for range 39 {
				response.Answers = append(response.Answers, response.Answers[0])
			}
		}
		return []dnsmessage.Message{response}
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
	request := recursiveRequest(t, "large.foreign.example.")
	response := queryWire(t, server, "udp", request)
	if !response.Truncated || len(response.Answers) != 0 || response.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("downstream UDP did not advertise complete TCP answer: %+v", response)
	}
	response = queryWire(t, server, "tcp", request)
	if response.Truncated || len(response.Answers) != 40 {
		t.Fatalf("downstream TCP lost upstream records: %+v", response)
	}
	if upstream.udp.Load() != 1 || upstream.tcp.Load() != 2 {
		t.Fatalf("wrong forwarding transports: UDP=%d TCP=%d", upstream.udp.Load(), upstream.tcp.Load())
	}
}

func TestTCPRejectsMismatchedAndTruncatedUpstreamReplies(t *testing.T) {
	for _, invalid := range []string{"id", "question", "truncated"} {
		t.Run(invalid, func(t *testing.T) {
			upstream := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
				response := upstreamAnswer(request)
				switch invalid {
				case "id":
					response.ID++
				case "question":
					response.Questions = append([]dnsmessage.Question(nil), response.Questions...)
					response.Questions[0].Type = dnsmessage.TypeAAAA
				case "truncated":
					response.Truncated = true
				}
				return []dnsmessage.Message{response}
			})
			server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
			if response := queryWire(t, server, "tcp", recursiveRequest(t, "foreign.example.")); response.RCode != dnsmessage.RCodeServerFailure || len(response.Answers) != 0 {
				t.Fatalf("invalid upstream TCP reply escaped: %+v", response)
			}
		})
	}
}

func TestForwardingUsesOnlyConfiguredFailoverEndpoints(t *testing.T) {
	unusable := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
		response := upstreamAnswer(request)
		response.ID++
		return []dnsmessage.Message{response}
	})
	selected := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
		return []dnsmessage.Message{upstreamAnswer(request)}
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{unusable.address, selected.address}})
	response := queryWire(t, server, "tcp", recursiveRequest(t, "foreign.example."))
	if response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) != 1 || unusable.tcp.Load() != 1 || selected.tcp.Load() != 1 {
		t.Fatalf("explicit failover failed: %+v first=%d second=%d", response, unusable.tcp.Load(), selected.tcp.Load())
	}
}

func TestIndirectForwardingLoopFailsWithoutAmplifyingQueries(t *testing.T) {
	var target atomic.Value
	upstream := newWireUpstream(t, func(network string, request dnsmessage.Message) []dnsmessage.Message {
		response, err := wireExchange(network, target.Load().(string), netip.Addr{}, request)
		if err != nil {
			t.Errorf("indirect loop relay: %v", err)
			return nil
		}
		return []dnsmessage.Message{response}
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
	target.Store(server.Address())
	for _, network := range []string{"udp", "tcp"} {
		response := queryWire(t, server, network, recursiveRequest(t, "loop.foreign.example."))
		if response.RCode != dnsmessage.RCodeServerFailure || len(response.Answers) != 0 {
			t.Fatalf("%s indirect loop did not fail: %+v", network, response)
		}
	}
	if upstream.udp.Load() != 1 || upstream.tcp.Load() != 1 {
		t.Fatalf("indirect loop amplified queries: UDP=%d TCP=%d", upstream.udp.Load(), upstream.tcp.Load())
	}
}

func TestForwardingHopLimitAndPrivateTraceDoNotLeak(t *testing.T) {
	upstream := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
		response := upstreamAnswer(request)
		response.Additionals = request.Additionals
		return []dnsmessage.Message{response}
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
	request := recursiveRequest(t, "foreign.example.")
	root, _ := dnsmessage.NewName(".")
	trace := append([]byte(loopMarker), make([]byte, maxForwardHops*16)...)
	request.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: root, Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: loopOptionCode, Data: trace}}}}}
	if response := queryWire(t, server, "udp", request); response.RCode != dnsmessage.RCodeServerFailure || upstream.udp.Load() != 0 {
		t.Fatalf("hop limit forwarded: %+v count=%d", response, upstream.udp.Load())
	}
	request.Additionals[0].Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 65024, Data: []byte("preserve-other-option")}}}
	response := queryWire(t, server, "udp", request)
	if response.RCode != dnsmessage.RCodeSuccess || len(response.Additionals) != 1 {
		t.Fatalf("forwarded EDNS response: %+v", response)
	}
	options := response.Additionals[0].Body.(*dnsmessage.OPTResource).Options
	if len(options) != 1 || options[0].Code != 65024 || string(options[0].Data) != "preserve-other-option" {
		t.Fatalf("private path leaked or unrelated EDNS option lost: %+v", options)
	}
}

func TestListenRejectsInvalidUpstreamsACLAndDirectLoops(t *testing.T) {
	for _, upstream := range []netip.AddrPort{{}, netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("0.0.0.0:53"), netip.MustParseAddrPort("[::]:53"), netip.MustParseAddrPort("224.0.0.1:53"), netip.MustParseAddrPort("[fe80::1%eth0]:53")} {
		if server, err := Listen(Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream}}); err == nil {
			_ = server.Close()
			t.Errorf("invalid upstream accepted: %v", upstream)
		}
	}
	for _, prefix := range []netip.Prefix{{}, netip.MustParsePrefix("::ffff:192.0.2.1/64")} {
		if server, err := Listen(Config{Address: "127.0.0.1:0", AllowedClients: []netip.Prefix{prefix}}); err == nil {
			_ = server.Close()
			t.Errorf("invalid forwarding ACL accepted: %v", prefix)
		}
	}
	for _, host := range []string{"127.0.0.1", "0.0.0.0"} {
		reservation, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(host)})
		if err != nil {
			t.Fatal(err)
		}
		port := reservation.Addr().(*net.TCPAddr).Port
		_ = reservation.Close()
		address := net.JoinHostPort(host, fmt.Sprint(port))
		upstream := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
		if server, err := Listen(Config{Address: address, Upstreams: []netip.AddrPort{upstream}}); err == nil {
			_ = server.Close()
			t.Fatalf("direct upstream loop accepted for %s", address)
		}
	}
}

func TestUpstreamReadHonorsContextCancellation(t *testing.T) {
	seen := make(chan struct{}, 1)
	upstream := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
		seen <- struct{}{}
		response := upstreamAnswer(request)
		response.ID++
		return []dnsmessage.Message{response}
	})
	request := recursiveRequest(t, "foreign.example.")
	packet, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := exchangeDNS(ctx, "udp", upstream.address.String(), packet, request.ID, request.Questions[0])
		result <- err
	}()
	waitTestSignal(t, seen)
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("unmatched reply satisfied cancelled query")
		}
	case <-time.After(time.Second):
		t.Fatal("upstream socket outlived its cancelled context")
	}
}

func TestMalformedAndUnsupportedQueriesNeverReachUpstream(t *testing.T) {
	upstream := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
		return []dnsmessage.Message{upstreamAnswer(request)}
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
	for _, network := range []string{"udp", "tcp"} {
		request := recursiveRequest(t, "foreign.example.")
		request.Questions = append(request.Questions, request.Questions[0])
		if response := queryWire(t, server, network, request); response.RCode != dnsmessage.RCodeFormatError {
			t.Fatalf("%s accepted a multi-question query: %+v", network, response)
		}
		request.Questions = request.Questions[:1]
		request.OpCode = 2
		if response := queryWire(t, server, network, request); response.RCode != dnsmessage.RCodeNotImplemented {
			t.Fatalf("%s accepted an unsupported opcode: %+v", network, response)
		}
	}
	if upstream.udp.Load()+upstream.tcp.Load() != 0 {
		t.Fatal("malformed or unsupported query reached the upstream")
	}
}

func TestMalformedUpstreamTCPFrameReturnsServerFailure(t *testing.T) {
	upstream, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		connection, err := upstream.AcceptTCP()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		var length [2]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return
		}
		packet := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(connection, packet); err != nil {
			return
		}
		// A valid length prefix does not make the one-byte body a DNS reply.
		_, _ = connection.Write([]byte{0, 1, 0})
	}()
	t.Cleanup(func() {
		_ = upstream.Close()
		<-finished
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.Addr().(*net.TCPAddr).AddrPort()}})
	response := queryWire(t, server, "tcp", recursiveRequest(t, "foreign.example."))
	if response.RCode != dnsmessage.RCodeServerFailure || len(response.Answers) != 0 {
		t.Fatalf("malformed upstream body escaped: %+v", response)
	}
}

func waitTestSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for the protocol peer")
	}
}
