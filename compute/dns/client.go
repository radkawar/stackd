package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Client queries one explicitly configured DNS endpoint. It never consults the
// host resolver or forwards missing names to an external DNS service.
type Client struct{ address string }

func NewClient(address string) (*Client, error) {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() {
		return nil, errors.New("DNS client requires an explicit IPv4 endpoint and nonzero port")
	}
	return &Client{address: endpoint.String()}, nil
}

// LookupCNAME returns the immediate CNAME target as a lower-case absolute name.
// Chasing a validation chain belongs to the consumer, which knows its hop limit
// and expected terminal name; this method does not recurse into foreign zones.
func (c *Client) LookupCNAME(ctx context.Context, name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, ".")) + "."
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return "", err
	}
	var nonce [2]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	question := dnsmessage.Question{Name: qname, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(nonce[:])}, Questions: []dnsmessage.Question{question}}
	packet, err := request.Pack()
	if err != nil {
		return "", err
	}
	response, err := c.exchange(ctx, "udp4", packet, request.ID, question)
	if err != nil {
		return "", err
	}
	if response.Truncated {
		response, err = c.exchange(ctx, "tcp4", packet, request.ID, question)
		if err != nil {
			return "", err
		}
	}
	if response.RCode != dnsmessage.RCodeSuccess {
		return "", &net.DNSError{Name: name, Server: c.address, Err: response.RCode.String(), IsNotFound: response.RCode == dnsmessage.RCodeNameError || response.RCode == dnsmessage.RCodeRefused, IsTemporary: response.RCode == dnsmessage.RCodeServerFailure}
	}
	for _, resource := range response.Answers {
		if resource.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(resource.Header.Name.String(), name) {
			continue
		}
		if cname, ok := resource.Body.(*dnsmessage.CNAMEResource); ok {
			return strings.ToLower(cname.CNAME.String()), nil
		}
	}
	return "", &net.DNSError{Name: name, Server: c.address, Err: "no CNAME record", IsNotFound: true}
}

func (c *Client) exchange(ctx context.Context, network string, packet []byte, id uint16, question dnsmessage.Question) (dnsmessage.Message, error) {
	var response dnsmessage.Message
	dialer := net.Dialer{Timeout: 3 * time.Second}
	connection, err := dialer.DialContext(ctx, network, c.address)
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
	cancel := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer cancel()
	var length [2]byte
	if network == "tcp4" {
		binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
		if _, err := connection.Write(length[:]); err != nil {
			return response, err
		}
	}
	if _, err := connection.Write(packet); err != nil {
		return response, err
	}
	buffer := make([]byte, 512)
	var n int
	if network == "tcp4" {
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return response, err
		}
		n = int(binary.BigEndian.Uint16(length[:]))
		if n > len(buffer) {
			buffer = make([]byte, n)
		}
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
	if response.ID != id || !response.Response || response.OpCode != 0 || len(response.Questions) != 1 || response.Questions[0] != question || network == "tcp4" && response.Truncated {
		return response, errors.New("DNS response does not match the query")
	}
	return response, nil
}
