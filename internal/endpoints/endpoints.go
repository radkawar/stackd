// Package endpoints constructs the explicit gateway resource namespace.
package endpoints

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ResourceURL retains the origin's transport and port, replacing only its host.
// An empty id constructs a regional service origin (for example SQS).
// An empty domain retains the validated origin without a resource namespace.
func ResourceURL(origin, domain, service, region, id string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("resource origin must be an explicit HTTP or WebSocket origin")
	}
	if u.RawPath != "" || strings.Contains(origin, "#") || strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("resource origin must not contain escaped paths or an empty port")
	}
	if _, err := netip.ParseAddr(u.Hostname()); err != nil && !validDomain(u.Hostname()) {
		return "", fmt.Errorf("resource origin has an invalid hostname")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", fmt.Errorf("resource origin has an invalid port")
		}
	}
	if domain != "" {
		if !validDomain(domain) || !validLabel(service) || !validLabel(region) || (id != "" && !validLabel(id)) {
			return "", fmt.Errorf("invalid resource hostname components")
		}
		host := service + "." + region + "." + strings.ToLower(domain)
		if id != "" {
			host = strings.ToLower(id) + "." + host
		}
		if len(host) > 253 {
			return "", fmt.Errorf("resource hostname is too long")
		}
		if port := u.Port(); port != "" {
			host = net.JoinHostPort(host, port)
		}
		u.Host = host
	}
	u.Path = "/"
	return u.String(), nil
}

// ResourceHost parses without mutating the original signed Host or URL.
// matched claims the configured service namespace, including malformed names;
// callers must reject a claimed name that has an empty region.
func ResourceHost(host, domain, service string) (id, region string, matched bool) {
	if domain == "" || !validDomain(domain) {
		return "", "", false
	}
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	suffix := "." + strings.ToLower(domain)
	prefix, ok := strings.CutSuffix(host, suffix)
	if !ok {
		return "", "", false
	}
	dot := strings.LastIndexByte(prefix, '.')
	if dot < 0 {
		return "", "", false
	}
	name := prefix[:dot]
	region = prefix[dot+1:]
	if name != service {
		var ok bool
		id, ok = strings.CutSuffix(name, "."+service)
		if !ok {
			return "", "", false
		}
		if !validLabel(id) {
			return "", "", true
		}
	}
	if !validLabel(region) {
		return "", "", true
	}
	return id, region, true
}

func validDomain(domain string) bool {
	if len(domain) > 253 || domain != strings.TrimSpace(domain) {
		return false
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	for {
		label, remaining, more := strings.Cut(domain, ".")
		if !validLabel(label) {
			return false
		}
		if !more {
			break
		}
		domain = remaining
	}
	return true
}
func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}
