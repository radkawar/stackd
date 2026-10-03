package eventpattern

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func cidr(pattern string) (func(value) bool, error) {
	lower, upper, err := cidrBounds(pattern)
	if err != nil {
		return nil, err
	}
	return func(v value) bool {
		candidate := v.text
		if v.kind == stringValue {
			parsed, err := ipAddress(candidate)
			if err != nil {
				return false
			}
			candidate = fmt.Sprintf("%X", parsed.AsSlice())
		} else if v.kind != numberValue {
			return false
		}
		// Native CIDR compares hexadecimal address ranges against leaf text;
		// broad ranges can also contain unquoted numeric JSON values.
		return candidate >= lower && candidate <= upper
	}, nil
}

// cidrBounds validates a subnet and returns its canonical inclusive range.
// The matcher and admission compiler share these lexical address bounds.
func cidrBounds(pattern string) (lower, upper string, err error) {
	host, suffix, found := strings.Cut(pattern, "/")
	if !found {
		return "", "", fmt.Errorf("CIDR requires a prefix length")
	}
	address, err := ipAddress(host)
	if err != nil {
		return "", "", err
	}
	bits, err := strconv.Atoi(suffix)
	if err != nil || bits < 0 || bits >= address.BitLen() {
		return "", "", fmt.Errorf("invalid CIDR prefix length %q", suffix)
	}
	bottom := netip.PrefixFrom(address, bits).Masked().Addr().AsSlice()
	top := append([]byte(nil), bottom...)
	for bit := bits; bit < address.BitLen(); bit++ {
		top[bit/8] |= 1 << (7 - bit%8)
	}
	return fmt.Sprintf("%X", bottom), fmt.Sprintf("%X", top), nil
}

func ipAddress(text string) (netip.Addr, error) {
	if strings.ContainsRune(text, ':') {
		if strings.ContainsAny(text, ".%") {
			return netip.Addr{}, fmt.Errorf("nonstandard IP address %q", text)
		}
		return netip.ParseAddr(text)
	}
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return netip.Addr{}, fmt.Errorf("nonstandard IP address %q", text)
	}
	var bytes [4]byte
	for i, part := range parts {
		for _, r := range part {
			if r < '0' || r > '9' {
				return netip.Addr{}, fmt.Errorf("invalid IPv4 address %q", text)
			}
		}
		number, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("invalid IPv4 address %q", text)
		}
		bytes[i] = byte(number)
	}
	return netip.AddrFrom4(bytes), nil
}
