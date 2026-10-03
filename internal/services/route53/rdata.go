package route53

import (
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"strconv"
	"strings"
)

var recordTypes = map[string]dnsmessage.Type{"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "CNAME": dnsmessage.TypeCNAME, "TXT": dnsmessage.TypeTXT, "MX": dnsmessage.TypeMX, "NS": dnsmessage.TypeNS, "SOA": dnsmessage.TypeSOA, "PTR": dnsmessage.TypePTR, "SRV": dnsmessage.TypeSRV, "CAA": 257}

func canonicalName(name string, wildcard bool) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", fmt.Errorf("invalid DNS name length")
	}
	// TODO: Comeback: escaped-octal/binary DNS labels need an escape-aware wire-name codec; reject rather than silently misroute them.
	for i, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("invalid DNS label length")
		}
		if wildcard && i == 0 && label == "*" {
			continue
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("DNS names require ASCII letters, digits, hyphen or underscore; wildcard is only permitted as the first label")
			}
		}
	}
	return name + ".", nil
}
func inZone(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }
func dnsName(v string) (dnsmessage.Name, error) {
	if v == "." {
		return dnsmessage.NewName(v)
	}
	n, e := canonicalName(v, false)
	if e != nil {
		return dnsmessage.Name{}, e
	}
	return dnsmessage.NewName(n)
}
func quotedStrings(v string) ([]string, error) {
	var out []string
	for len(strings.TrimSpace(v)) > 0 {
		v = strings.TrimSpace(v)
		if v[0] != '"' {
			return nil, fmt.Errorf("TXT and CAA text must be quoted")
		}
		v = v[1:]
		var b strings.Builder
		closed := false
		for len(v) > 0 {
			c := v[0]
			v = v[1:]
			if c == '"' {
				closed = true
				break
			}
			if c == '\\' {
				if len(v) == 0 {
					return nil, fmt.Errorf("unterminated escape")
				}
				if len(v) >= 3 && v[0] >= '0' && v[0] <= '9' && v[1] >= '0' && v[1] <= '9' && v[2] >= '0' && v[2] <= '9' {
					n, e := strconv.ParseUint(v[:3], 10, 8)
					if e != nil {
						return nil, e
					}
					c = byte(n)
					v = v[3:]
				} else {
					c = v[0]
					v = v[1:]
				}
			}
			b.WriteByte(c)
		}
		if !closed {
			return nil, fmt.Errorf("unterminated quoted text")
		}
		out = append(out, b.String())
		if len(v) > 0 && v[0] != ' ' && v[0] != '\t' {
			return nil, fmt.Errorf("quoted strings must be separated by whitespace")
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty record data")
	}
	return out, nil
}
func quoteDNS(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := range len(v) {
		c := v[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 32 || c > 126:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
func parseRData(kind, value string) (dnsmessage.ResourceBody, string, error) {
	bad := func() (dnsmessage.ResourceBody, string, error) {
		return nil, "", fmt.Errorf("invalid %s resource record data", kind)
	}
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 4000 {
		return bad()
	}
	f := strings.Fields(value)
	number := func(s string, bits int) (uint64, error) { return strconv.ParseUint(s, 10, bits) }
	switch kind {
	case "A", "AAAA":
		a, e := netip.ParseAddr(value)
		if e != nil || a.Zone() != "" {
			return bad()
		}
		if kind == "A" {
			if !a.Is4() {
				return bad()
			}
			return &dnsmessage.AResource{A: a.As4()}, a.String(), nil
		}
		if !a.Is6() || a.Is4In6() {
			return bad()
		}
		return &dnsmessage.AAAAResource{AAAA: a.As16()}, a.String(), nil
	case "NS", "CNAME", "PTR":
		if len(f) != 1 {
			return bad()
		}
		n, e := dnsName(value)
		if e != nil {
			return bad()
		}
		switch kind {
		case "NS":
			return &dnsmessage.NSResource{NS: n}, n.String(), nil
		case "CNAME":
			return &dnsmessage.CNAMEResource{CNAME: n}, n.String(), nil
		default:
			return &dnsmessage.PTRResource{PTR: n}, n.String(), nil
		}
	case "TXT":
		texts, e := quotedStrings(value)
		if e != nil {
			return bad()
		}
		canonical := make([]string, len(texts))
		for i, t := range texts {
			if len(t) > 255 {
				return bad()
			}
			canonical[i] = quoteDNS(t)
		}
		return &dnsmessage.TXTResource{TXT: texts}, strings.Join(canonical, " "), nil
	case "MX":
		if len(f) != 2 {
			return bad()
		}
		p, e := number(f[0], 16)
		if e != nil {
			return bad()
		}
		n, e := dnsName(f[1])
		if e != nil {
			return bad()
		}
		return &dnsmessage.MXResource{Pref: uint16(p), MX: n}, fmt.Sprintf("%d %s", p, n.String()), nil
	case "SOA":
		if len(f) != 7 {
			return bad()
		}
		ns, e := dnsName(f[0])
		if e != nil {
			return bad()
		}
		mbox, e := dnsName(f[1])
		if e != nil {
			return bad()
		}
		var v [5]uint32
		for i := range v {
			n, e := number(f[i+2], 32)
			if e != nil {
				return bad()
			}
			v[i] = uint32(n)
		}
		return &dnsmessage.SOAResource{NS: ns, MBox: mbox, Serial: v[0], Refresh: v[1], Retry: v[2], Expire: v[3], MinTTL: v[4]}, fmt.Sprintf("%s %s %d %d %d %d %d", ns.String(), mbox.String(), v[0], v[1], v[2], v[3], v[4]), nil
	case "SRV":
		if len(f) != 4 {
			return bad()
		}
		var v [3]uint16
		for i := range v {
			n, e := number(f[i], 16)
			if e != nil {
				return bad()
			}
			v[i] = uint16(n)
		}
		n, e := dnsName(f[3])
		if e != nil {
			return bad()
		}
		return &dnsmessage.SRVResource{Priority: v[0], Weight: v[1], Port: v[2], Target: n}, fmt.Sprintf("%d %d %d %s", v[0], v[1], v[2], n.String()), nil
	case "CAA":
		if len(f) < 3 {
			return bad()
		}
		flag, e := number(f[0], 8)
		if e != nil {
			return bad()
		}
		tag := f[1]
		if len(tag) < 1 || len(tag) > 15 {
			return bad()
		}
		for _, c := range tag {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				return bad()
			}
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(value, f[0])), tag))
		text, e := quotedStrings(rest)
		if e != nil || len(text) != 1 {
			return bad()
		}
		data := append([]byte{byte(flag), byte(len(tag))}, []byte(tag)...)
		data = append(data, []byte(text[0])...)
		return &dnsmessage.UnknownResource{Type: 257, Data: data}, fmt.Sprintf("%d %s %s", flag, tag, quoteDNS(text[0])), nil
	}
	return bad()
}
