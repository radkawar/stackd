package policy

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var conditionDecimal = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// Decimal normalization preserves precision and scale for simulation output
// and numeric comparisons of string context. For
// example, 01.00 becomes 1.00, while 1e2 becomes 1E+2. Parsing an integer with
// base inference would incorrectly interpret leading zeroes as octal.
func conditionNumber(value string) (string, error) {
	if !conditionDecimal.MatchString(value) {
		return "", fmt.Errorf("%w: expected numeric format", ErrInvalidRequest)
	}
	negative := strings.HasPrefix(value, "-")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "-"), "+")
	exponent := int64(0)
	if index := strings.IndexAny(value, "eE"); index >= 0 {
		var err error
		exponent, err = strconv.ParseInt(value[index+1:], 10, 32)
		if err != nil {
			return "", fmt.Errorf("%w: numeric exponent is out of range", ErrInvalidRequest)
		}
		value = value[:index]
	}
	scale := -exponent
	if index := strings.IndexByte(value, '.'); index >= 0 {
		scale += int64(len(value) - index - 1)
		value = value[:index] + value[index+1:]
	}
	value = strings.TrimLeft(value, "0")
	if value == "" {
		value = "0"
		negative = false
	}
	adjusted := int64(len(value)) - scale - 1
	var result string
	if scale >= 0 && adjusted >= -6 {
		point := int64(len(value)) - scale
		switch {
		case scale == 0:
			result = value
		case point > 0:
			result = value[:point] + "." + value[point:]
		default:
			result = "0." + strings.Repeat("0", int(-point)) + value
		}
	} else {
		result = value[:1]
		if len(value) > 1 {
			result += "." + value[1:]
		}
		result += "E"
		if adjusted >= 0 {
			result += "+"
		}
		result += strconv.FormatInt(adjusted, 10)
	}
	if negative {
		result = "-" + result
	}
	return result, nil
}

func conditionDate(value string) (time.Time, error) {
	if parsed, err := parseDate(value); err == nil {
		return parsed, nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02T15:04", "2006-01-02T15"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: expected DateTime format", ErrInvalidRequest)
}

// Request IPs normalize IPv4-mapped IPv6 addresses to IPv4 for comparison.
// Policy networks retain their written address family, so a mapped IPv6
// network cannot match an IPv4 request. Simulation preserves the original
// context spelling for String comparisons; normalization belongs here.
func conditionAddress(value string) (netip.Addr, error) {
	address, err := parseConditionIP(value)
	return address.Unmap(), err
}

func conditionPrefix(value string) (netip.Prefix, error) {
	host, suffix, hasPrefix := strings.Cut(value, "/")
	address, err := parseConditionIP(host)
	if err != nil {
		return netip.Prefix{}, err
	}
	if address.Is6() && strings.Contains(host, ".") {
		return netip.Prefix{}, fmt.Errorf("IPv6 policy networks require hexadecimal notation")
	}
	bits := address.BitLen()
	if hasPrefix {
		bits, err = strconv.Atoi(suffix)
		if err != nil || bits < 0 || bits > address.BitLen() {
			return netip.Prefix{}, fmt.Errorf("expected IP address or CIDR network")
		}
	}
	prefix := netip.PrefixFrom(address, bits)
	if address.Is6() && prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("IPv6 policy networks must have zero host bits")
	}
	return prefix, nil
}

func parseConditionIP(value string) (netip.Addr, error) {
	// AWS accepts an empty leading group as zero and ignores a trailing
	// separator. One compression run may have an adjacent empty group;
	// multiple compression runs remain invalid. Preserve the caller's text
	// elsewhere so this normalization only affects IP comparisons.
	if strings.Count(value, ":") > 1 {
		if strings.HasPrefix(value, ":") && !strings.HasPrefix(value, "::") {
			value = "0" + value
		}
		if left, right, compressed := strings.Cut(value, "::"); compressed && !strings.Contains(right, "::") {
			value = left + "::" + strings.Trim(right, ":")
		} else if !compressed {
			value = strings.TrimSuffix(value, ":")
		}
	}
	if strings.Count(value, ".") == 3 && !strings.Contains(value, ":") {
		parts := strings.Split(value, ".")
		for index, part := range parts {
			if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return netip.Addr{}, fmt.Errorf("%w: expected IP address", ErrInvalidRequest)
			}
			number, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return netip.Addr{}, fmt.Errorf("%w: expected IP address", ErrInvalidRequest)
			}
			parts[index] = strconv.FormatUint(number, 10)
		}
		value = strings.Join(parts, ".")
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is6() && strings.Contains(value, ".") && !address.Is4In6() {
		return netip.Addr{}, fmt.Errorf("%w: expected IP address", ErrInvalidRequest)
	}
	return address, nil
}
