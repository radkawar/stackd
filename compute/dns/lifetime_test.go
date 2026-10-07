package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestRedirectACLIsEnforcedOnRealUDPAndTCPPeers(t *testing.T) {
	upstream := newWireUpstream(t, func(_ string, request dnsmessage.Message) []dnsmessage.Message {
		return []dnsmessage.Message{upstreamAnswer(request)}
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
	redirect, err := NewRedirect("aws.example", []netip.Addr{netip.MustParseAddr("127.0.0.9")}, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Register(redirect); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "tcp"} {
		for _, scenario := range []struct {
			source        string
			authoritative bool
			address       [4]byte
		}{
			{"127.0.0.1", true, [4]byte{127, 0, 0, 9}},
			{"127.0.0.2", false, [4]byte{192, 0, 2, 19}},
		} {
			response, err := wireExchange(network, server.Address(), netip.MustParseAddr(scenario.source), recursiveRequest(t, "sqs.region.aws.example."))
			if err != nil {
				t.Fatalf("%s client %s: %v", network, scenario.source, err)
			}
			if response.RCode != dnsmessage.RCodeSuccess || response.Authoritative != scenario.authoritative || len(response.Answers) != 1 || response.Answers[0].Body.(*dnsmessage.AResource).A != scenario.address {
				t.Fatalf("%s peer %s received wrong authority: %+v", network, scenario.source, response)
			}
		}
	}
	if upstream.udp.Load() != 1 || upstream.tcp.Load() != 1 {
		t.Fatalf("redirect peers leaked upstream or denied peer was intercepted: UDP=%d TCP=%d", upstream.udp.Load(), upstream.tcp.Load())
	}
}

func TestOwnerWithdrawalWaitsForReadersAndDoesNotAffectOtherOwners(t *testing.T) {
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0"})
	entered := make(chan struct{})
	finish := make(chan struct{})
	unblocked := false
	defer func() {
		if !unblocked {
			close(finish)
		}
	}()
	release, err := server.Register(resolverFunc(func(_ context.Context, question dnsmessage.Question) (Result, error) {
		if question.Name.String() != "current.example." {
			return Result{}, nil
		}
		close(entered)
		<-finish
		return Result{Authoritative: true, Exists: true}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Register(resolverFunc(func(_ context.Context, question dnsmessage.Question) (Result, error) {
		if question.Name.String() == "other.example." {
			return Result{Authoritative: true, Exists: true}, nil
		}
		return Result{}, nil
	})); err != nil {
		t.Fatal(err)
	}
	request := recursiveRequest(t, "current.example.")
	queryDone := make(chan error, 1)
	go func() {
		response, err := wireExchange("tcp", server.Address(), netip.Addr{}, request)
		if err == nil && (response.RCode != dnsmessage.RCodeSuccess || !response.Authoritative) {
			err = errors.New("in-flight owner answer lost during withdrawal")
		}
		queryDone <- err
	}()
	waitTestSignal(t, entered)
	withdrawStarted, withdrawn := make(chan struct{}), make(chan struct{})
	go func() {
		close(withdrawStarted)
		release()
		close(withdrawn)
	}()
	<-withdrawStarted
	select {
	case <-withdrawn:
		t.Fatal("release returned while the owner was still reading retained state")
	case <-time.After(25 * time.Millisecond):
	}
	close(finish)
	unblocked = true
	select {
	case <-withdrawn:
	case <-time.After(time.Second):
		t.Fatal("withdrawal did not finish after its reader left")
	}
	select {
	case err := <-queryDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("in-flight query did not leave its withdrawn owner")
	}
	release()
	if response := queryWire(t, server, "udp", request); response.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("withdrawn current owner still served: %+v", response)
	}
	if response := queryWire(t, server, "tcp", recursiveRequest(t, "other.example.")); !response.Authoritative || response.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("unrelated owner removed by withdrawal: %+v", response)
	}
}

func TestCloseCancelsOwnerBeforeWaitingForItsReadLock(t *testing.T) {
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0"})
	entered := make(chan struct{})
	_, err := server.Register(resolverFunc(func(ctx context.Context, _ dnsmessage.Question) (Result, error) {
		close(entered)
		<-ctx.Done()
		return Result{Authoritative: true}, ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := recursiveRequest(t, "current.example.")
	queryDone := make(chan struct{})
	go func() {
		_, _ = wireExchange("tcp", server.Address(), netip.Addr{}, request)
		close(queryDone)
	}()
	waitTestSignal(t, entered)
	closed := make(chan error, 2)
	go func() { closed <- server.Close() }()
	go func() { closed <- server.Close() }()
	for range 2 {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("close waited for owner timeout instead of cancelling first")
		}
	}
	select {
	case <-queryDone:
	case <-time.After(time.Second):
		t.Fatal("TCP serving connection survived Close")
	}
	if _, err := server.Register(resolverFunc(func(context.Context, dnsmessage.Question) (Result, error) { return Result{}, nil })); err == nil {
		t.Fatal("closed endpoint accepted a new owner")
	}
}

func TestCloseCancelsBlockedUpstreamAndIdleTCPConnections(t *testing.T) {
	seen := make(chan struct{}, 1)
	upstream := newWireUpstream(t, func(_ string, _ dnsmessage.Message) []dnsmessage.Message {
		seen <- struct{}{}
		return nil
	})
	server := listenTestDNS(t, Config{Address: "127.0.0.1:0", Upstreams: []netip.AddrPort{upstream.address}})
	idle, err := net.Dial("tcp", server.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	client, err := net.Dial("udp", server.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := recursiveRequest(t, "foreign.example.")
	packet, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	waitTestSignal(t, seen)
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("forwarding socket outlived the server's Close")
	}
	_ = idle.SetReadDeadline(time.Now().Add(time.Second))
	var probe [1]byte
	if _, err := idle.Read(probe[:]); err == nil {
		t.Fatal("idle TCP connection remained usable after Close")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("idle TCP connection was not actively closed")
	}
}
