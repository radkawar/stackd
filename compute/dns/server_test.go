package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type resolverFunc func(context.Context, dnsmessage.Question) (Result, error)

func (f resolverFunc) LookupDNS(ctx context.Context, q dnsmessage.Question) (Result, error) {
	return f(ctx, q)
}

func exchange(t *testing.T, server *Server, protocol, name string, typ dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 1987, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: qname, Type: typ, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout(protocol, server.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 65535)
	var length [2]byte
	if protocol == "tcp" {
		binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
		packet = append(length[:], packet...)
	}
	if _, err = connection.Write(packet); err != nil {
		t.Fatal(err)
	}
	var n int
	if protocol == "tcp" {
		if _, err = io.ReadFull(connection, length[:]); err != nil {
			t.Fatal(err)
		}
		n = int(binary.BigEndian.Uint16(length[:]))
		_, err = io.ReadFull(connection, buffer[:n])
	} else {
		n, err = connection.Read(buffer)
	}
	if err != nil {
		t.Fatal(err)
	}
	var response dnsmessage.Message
	if err = response.Unpack(buffer[:n]); err != nil {
		t.Fatal(err)
	}
	if response.ID != 1987 || !response.Response || response.RecursionAvailable {
		t.Fatalf("bad reply header: %+v", response.Header)
	}
	return response
}

func TestAuthoritativeUDPAndTCPWithdrawal(t *testing.T) {
	s, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner := func(name string) Resolver {
		return resolverFunc(func(_ context.Context, q dnsmessage.Question) (Result, error) {
			if q.Name.String() != name {
				return Result{}, nil
			}
			out := Result{Authoritative: true, Exists: true}
			if q.Type == dnsmessage.TypeA {
				out.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
			}
			return out, nil
		})
	}
	release, err := s.Register(owner("first.example."))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Register(owner("second.example."))
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"udp", "tcp"} {
		out := exchange(t, s, protocol, "first.example.", dnsmessage.TypeA)
		if !out.Authoritative || out.RCode != dnsmessage.RCodeSuccess || len(out.Answers) != 1 || out.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{127, 0, 0, 1} || out.Answers[0].Header.TTL != 60 {
			t.Fatalf("A result: %+v", out)
		}
		out = exchange(t, s, protocol, "first.example.", dnsmessage.TypeAAAA)
		if out.RCode != dnsmessage.RCodeSuccess || len(out.Answers) != 0 {
			t.Fatalf("AAAA fabricated: %+v", out)
		}
	}
	release()
	release()
	if out := exchange(t, s, "udp", "first.example.", dnsmessage.TypeA); out.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("released owner still served: %+v", out)
	}
	if out := exchange(t, s, "tcp", "second.example.", dnsmessage.TypeA); len(out.Answers) != 1 {
		t.Fatalf("unrelated owner removed: %+v", out)
	}
}

func TestTruncatedUDPHasCompleteTCPAnswer(t *testing.T) {
	s, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.Register(resolverFunc(func(_ context.Context, q dnsmessage.Question) (Result, error) {
		out := Result{Authoritative: true, Exists: true}
		for i := 1; i <= 40; i++ {
			out.Answers = append(out.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, byte(i)}}})
		}
		return out, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if out := exchange(t, s, "udp", "large.example.", dnsmessage.TypeA); !out.Truncated || len(out.Answers) != 0 {
		t.Fatalf("UDP result: %+v", out)
	}
	out := exchange(t, s, "tcp", "large.example.", dnsmessage.TypeA)
	if out.Truncated || len(out.Answers) != 40 || out.Answers[39].Body.(*dnsmessage.AResource).A != [4]byte{10, 0, 0, 40} {
		t.Fatalf("TCP result: %+v", out)
	}
}
