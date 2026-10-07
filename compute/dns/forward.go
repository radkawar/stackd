package dns

import (
	"bytes"
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

// A private EDNS option carries a bounded path of random endpoint identities.
// It prevents indirect cycles between cooperating forwarders without retaining
// questions or a second resource registry. Non-cooperating upstreams remain
// bounded by the serving context and socket deadlines.
const loopOptionCode uint16 = 65023
const loopMarker = "SDN1"
const maxForwardHops = 8

// Parsing resources copies wire data, so an exchange can release its receive
// buffer as soon as it returns the parsed response.
var exchangeBuffers sync.Pool

func rejectSelfUpstreams(bound netip.AddrPort, upstreams []netip.AddrPort) error {
	var local []net.Addr
	for _, upstream := range upstreams {
		if upstream.Port() != bound.Port() {
			continue
		}
		address := upstream.Addr().Unmap()
		if address == bound.Addr().Unmap() {
			return errors.New("DNS upstream points to this listener")
		}
		if !bound.Addr().IsUnspecified() || !address.Is4() {
			continue
		}
		if address.IsLoopback() {
			return errors.New("DNS upstream points to this wildcard listener")
		}
		if local == nil {
			var err error
			local, err = net.InterfaceAddrs()
			if err != nil {
				return err
			}
		}
		for _, candidate := range local {
			prefix, err := netip.ParsePrefix(candidate.String())
			if err == nil && prefix.Addr().Unmap() == address {
				return errors.New("DNS upstream points to this wildcard listener")
			}
		}
	}
	return nil
}

func (s *Server) forward(ctx context.Context, request dnsmessage.Message, tcp bool) (dnsmessage.Message, error) {
	var response dnsmessage.Message
	if err := s.appendLoopTrace(&request); err != nil {
		return response, err
	}
	var nonce [2]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return response, err
	}
	request.ID = binary.BigEndian.Uint16(nonce[:])
	packet, err := request.Pack()
	if err != nil {
		return response, err
	}
	for i, upstream := range s.upstreams {
		if err := ctx.Err(); err != nil {
			return response, err
		}
		// Transport failures may try another explicitly selected endpoint. Share
		// the total serving deadline so an unavailable first endpoint cannot
		// consume every later endpoint's opportunity.
		attemptCtx := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
			attemptCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(s.upstreams)-i))
		}
		network := "udp"
		if tcp {
			network = "tcp"
		}
		response, err = exchangeDNS(attemptCtx, network, upstream.String(), packet, request.ID, request.Questions[0])
		if err == nil && response.Truncated {
			response, err = exchangeDNS(attemptCtx, "tcp", upstream.String(), packet, request.ID, request.Questions[0])
		}
		cancel()
		if err == nil {
			removeLoopTrace(&response)
			return response, nil
		}
	}
	return response, err
}

func (s *Server) appendLoopTrace(request *dnsmessage.Message) error {
	var opt *dnsmessage.OPTResource
	for _, resource := range request.Additionals {
		if resource.Header.Type != dnsmessage.TypeOPT {
			continue
		}
		if opt != nil || resource.Header.Name.String() != "." {
			return errors.New("DNS query has invalid EDNS options")
		}
		var ok bool
		opt, ok = resource.Body.(*dnsmessage.OPTResource)
		if !ok {
			return errors.New("DNS query has invalid EDNS data")
		}
	}
	if opt == nil {
		root, _ := dnsmessage.NewName(".")
		opt = &dnsmessage.OPTResource{}
		request.Additionals = append(request.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: root, Type: dnsmessage.TypeOPT, Class: 512}, Body: opt,
		})
	}
	index := -1
	var trace []byte
	for i, option := range opt.Options {
		if option.Code != loopOptionCode {
			continue
		}
		if index != -1 || !bytes.HasPrefix(option.Data, []byte(loopMarker)) || (len(option.Data)-len(loopMarker))%len(s.loopToken) != 0 {
			return errors.New("DNS query has an invalid forwarding path")
		}
		index, trace = i, option.Data
	}
	if trace == nil {
		trace = []byte(loopMarker)
	}
	if (len(trace)-len(loopMarker))/len(s.loopToken) >= maxForwardHops {
		return errors.New("DNS forwarding hop limit exceeded")
	}
	for offset := len(loopMarker); offset < len(trace); offset += len(s.loopToken) {
		if bytes.Equal(trace[offset:offset+len(s.loopToken)], s.loopToken[:]) {
			return errors.New("DNS forwarding loop detected")
		}
	}
	trace = append(trace, s.loopToken[:]...)
	if index == -1 {
		opt.Options = append(opt.Options, dnsmessage.Option{Code: loopOptionCode, Data: trace})
	} else {
		opt.Options[index].Data = trace
	}
	return nil
}

func removeLoopTrace(response *dnsmessage.Message) {
	for _, resource := range response.Additionals {
		opt, ok := resource.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		options := opt.Options[:0]
		for _, option := range opt.Options {
			if option.Code != loopOptionCode || !bytes.HasPrefix(option.Data, []byte(loopMarker)) {
				options = append(options, option)
			}
		}
		opt.Options = options
	}
}

func matchingQuestion(actual, wanted dnsmessage.Question) bool {
	return actual.Type == wanted.Type && actual.Class == wanted.Class && equalDNSName(actual.Name.String(), wanted.Name.String())
}

// DNS case insensitivity covers ASCII letters, not Unicode equivalences.
func equalDNSName(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range len(left) {
		a, b := left[i], right[i]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func exchangeDNS(ctx context.Context, network, address string, packet []byte, id uint16, question dnsmessage.Question) (dnsmessage.Message, error) {
	var response dnsmessage.Message
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return response, err
	}
	defer connection.Close()
	deadline := time.Now().Add(3 * time.Second)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return response, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	tcp := network == "tcp" || network == "tcp4" || network == "tcp6"
	if tcp {
		err = writeTCPMessage(connection, packet)
	} else {
		_, err = connection.Write(packet)
	}
	if err != nil {
		return response, err
	}
	buffer, ok := exchangeBuffers.Get().(*[65535]byte)
	if !ok {
		buffer = new([65535]byte)
	}
	defer exchangeBuffers.Put(buffer)
	var length [2]byte
	for {
		var n int
		if tcp {
			if _, err := io.ReadFull(connection, length[:]); err != nil {
				return response, err
			}
			n = int(binary.BigEndian.Uint16(length[:]))
			_, err = io.ReadFull(connection, buffer[:n])
		} else {
			n, err = connection.Read(buffer[:])
		}
		if err != nil {
			return response, err
		}
		var parser dnsmessage.Parser
		header, parseErr := parser.Start(buffer[:n])
		var questions []dnsmessage.Question
		if parseErr == nil {
			questions, parseErr = parser.AllQuestions()
		}
		if parseErr != nil || !header.Response || header.ID != id || header.OpCode != 0 || len(questions) != 1 || !matchingQuestion(questions[0], question) {
			if tcp {
				return response, errors.New("DNS response does not match the query")
			}
			// UDP can contain unrelated or stale datagrams. They cannot satisfy
			// this query and do not extend the original deadline.
			continue
		}
		if header.Truncated {
			if tcp {
				return response, errors.New("DNS TCP response is truncated")
			}
			return dnsmessage.Message{Header: header, Questions: questions}, nil
		}
		response = dnsmessage.Message{Header: header, Questions: questions}
		response.Answers, parseErr = parser.AllAnswers()
		if parseErr == nil {
			response.Authorities, parseErr = parser.AllAuthorities()
		}
		if parseErr == nil {
			response.Additionals, parseErr = parser.AllAdditionals()
		}
		if parseErr != nil {
			if tcp {
				return response, parseErr
			}
			continue
		}
		return response, nil
	}
}

func writeTCPMessage(connection net.Conn, packet []byte) error {
	if len(packet) == 0 || len(packet) > 65535 {
		return errors.New("DNS TCP message length is invalid")
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
	if err := writeAll(connection, length[:]); err != nil {
		return err
	}
	return writeAll(connection, packet)
}

func writeAll(writer io.Writer, packet []byte) error {
	for len(packet) != 0 {
		n, err := writer.Write(packet)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}
