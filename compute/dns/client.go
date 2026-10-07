package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"

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
	response, err := exchangeDNS(ctx, "udp4", c.address, packet, request.ID, question)
	if err != nil {
		return "", err
	}
	if response.Truncated {
		response, err = exchangeDNS(ctx, "tcp4", c.address, packet, request.ID, question)
		if err != nil {
			return "", err
		}
	}
	if response.RCode != dnsmessage.RCodeSuccess {
		return "", &net.DNSError{Name: name, Server: c.address, Err: response.RCode.String(), IsNotFound: response.RCode == dnsmessage.RCodeNameError || response.RCode == dnsmessage.RCodeRefused, IsTemporary: response.RCode == dnsmessage.RCodeServerFailure}
	}
	for _, resource := range response.Answers {
		if resource.Header.Class != dnsmessage.ClassINET || !equalDNSName(resource.Header.Name.String(), name) {
			continue
		}
		if cname, ok := resource.Body.(*dnsmessage.CNAMEResource); ok {
			return strings.ToLower(cname.CNAME.String()), nil
		}
	}
	return "", &net.DNSError{Name: name, Server: c.address, Err: "no CNAME record", IsNotFound: true}
}
