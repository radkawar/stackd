package elbv2

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/elbv2"
)

// WeightedTargetGroup is a forwarding destination; zero weight disables selection.
type WeightedTargetGroup struct {
	ARN    string
	Weight int
}

// MatchRule evaluates numeric priorities before the default, without mutating rules.
// Callers must reject unsupported transforms during admission.
func MatchRule(rules api.Rules, r *http.Request) (api.Rule, bool) {
	var selected api.Rule
	found, best := false, 50002
	for _, rule := range rules {
		priority := 50001
		if rule.IsDefault == nil || !bool(*rule.IsDefault) {
			if rule.Priority == nil {
				continue
			}
			n, err := strconv.Atoi(string(*rule.Priority))
			if err != nil || n < 1 || n > 50000 {
				continue
			}
			priority = n
		}
		if priority < best && MatchConditions(rule.Conditions, r) {
			selected, found, best = rule, true, priority
		}
	}
	return selected, found
}

// MatchConditions ANDs conditions and ORs evaluations within each condition.
// Source IP uses the peer address, never client-supplied forwarding headers.
func MatchConditions(conditions api.RuleConditionList, r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	for _, c := range conditions {
		if !matchCondition(c, r) {
			return false
		}
	}
	return true
}

func matchCondition(c api.RuleCondition, r *http.Request) bool {
	if c.Field == nil {
		return false
	}
	values, regexes := conditionPatterns(c)
	switch string(*c.Field) {
	case "host-header":
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		return matchPatterns(values, regexes, host, true)
	case "path-pattern":
		return matchPatterns(values, regexes, normalizedPath(r.URL), false)
	case "http-header":
		if c.HttpHeaderConfig == nil || c.HttpHeaderConfig.HttpHeaderName == nil {
			return false
		}
		name := string(*c.HttpHeaderConfig.HttpHeaderName)
		if strings.EqualFold(name, "Host") {
			return false
		}
		for _, value := range r.Header.Values(name) {
			if matchPatterns(values, regexes, value, true) {
				return true
			}
		}
	case "http-request-method":
		for _, value := range values {
			if string(value) == r.Method {
				return true
			}
		}
	case "query-string":
		if c.QueryStringConfig == nil {
			return false
		}
		query := r.URL.Query()
		for _, pair := range c.QueryStringConfig.Values {
			if pair.Value == nil {
				continue
			}
			for key, entries := range query {
				if pair.Key != nil && (!visibleASCII(key) || !wildcardMatch(string(*pair.Key), key, true, true)) {
					continue
				}
				for _, value := range entries {
					if visibleASCII(value) && wildcardMatch(string(*pair.Value), value, true, true) {
						return true
					}
				}
			}
		}
	case "source-ip":
		peer := r.RemoteAddr
		if host, _, err := net.SplitHostPort(peer); err == nil {
			peer = host
		}
		addr, err := netip.ParseAddr(peer)
		if err != nil {
			return false
		}
		addr = addr.Unmap()
		for _, value := range values {
			prefix, err := netip.ParsePrefix(string(value))
			if err == nil && prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func conditionPatterns(c api.RuleCondition) (api.ListOfString, api.ListOfString) {
	switch {
	case c.HostHeaderConfig != nil:
		return c.HostHeaderConfig.Values, c.HostHeaderConfig.RegexValues
	case c.PathPatternConfig != nil:
		return c.PathPatternConfig.Values, c.PathPatternConfig.RegexValues
	case c.HttpHeaderConfig != nil:
		return c.HttpHeaderConfig.Values, c.HttpHeaderConfig.RegexValues
	case c.HttpRequestMethodConfig != nil:
		return c.HttpRequestMethodConfig.Values, nil
	case c.SourceIpConfig != nil:
		return c.SourceIpConfig.Values, nil
	default:
		return c.Values, c.RegexValues
	}
}

func matchPatterns(values, regexes api.ListOfString, value string, fold bool) bool {
	if !visibleASCII(value) {
		return false
	}
	for _, pattern := range values {
		if wildcardMatch(string(pattern), value, fold, false) {
			return true
		}
	}
	for _, pattern := range regexes {
		expression := string(pattern)
		if fold {
			expression = "(?i:" + expression + ")"
		}
		matched, err := regexp.MatchString(expression, value)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// wildcardMatch implements AWS '*' and '?' rather than filesystem glob syntax.
// Query strings additionally support backslash-escaped literal wildcards.
func wildcardMatch(pattern, value string, fold, escape bool) bool {
	p, v, star, retry := 0, 0, -1, 0
	for v < len(value) {
		if p < len(pattern) {
			ch, width, literal := pattern[p], 1, false
			if escape && ch == '\\' && p+1 < len(pattern) {
				ch, width, literal = pattern[p+1], 2, true
			}
			if !literal && ch == '*' {
				star, retry, p = p, v, p+1
				continue
			}
			if (!literal && ch == '?') || equalASCII(ch, value[v], fold) {
				p, v = p+width, v+1
				continue
			}
		}
		if star < 0 {
			return false
		}
		retry++
		p, v = star+1, retry
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func equalASCII(a, b byte, fold bool) bool {
	if fold {
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
	}
	return a == b
}

func visibleASCII(value string) bool {
	for i := range value {
		if value[i] < 32 || value[i] > 126 {
			return false
		}
	}
	return true
}

// Normalize dot segments after decoding unreserved octets, but retain escaped
// separators: %2F must not create a path segment boundary during rule evaluation.
func normalizedPath(u *url.URL) string {
	escaped := u.EscapedPath()
	if escaped == "" {
		return "/"
	}
	var b strings.Builder
	b.Grow(len(escaped))
	for i := 0; i < len(escaped); i++ {
		if escaped[i] == '%' && i+2 < len(escaped) {
			n, err := strconv.ParseUint(escaped[i+1:i+3], 16, 8)
			if err == nil {
				ch := byte(n)
				if isUnreserved(ch) {
					b.WriteByte(ch)
				} else {
					b.WriteString(strings.ToUpper(escaped[i : i+3]))
				}
				i += 2
				continue
			}
		}
		b.WriteByte(escaped[i])
	}
	value := b.String()
	clean := path.Clean(value)
	if (strings.HasSuffix(value, "/") || strings.HasSuffix(value, "/.") || strings.HasSuffix(value, "/..")) && clean != "/" {
		clean += "/"
	}
	return clean
}

func isUnreserved(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("-._~", rune(ch))
}

// ForwardGroups returns configured destinations in their declared order.
// The single-group form has an implicit weight of one.
func ForwardGroups(action api.Action) []WeightedTargetGroup {
	if action.Type == nil || *action.Type != api.ActionTypeEnumFORWARD {
		return nil
	}
	if action.ForwardConfig != nil && len(action.ForwardConfig.TargetGroups) > 0 {
		groups := make([]WeightedTargetGroup, 0, len(action.ForwardConfig.TargetGroups))
		for _, group := range action.ForwardConfig.TargetGroups {
			if group.TargetGroupArn == nil {
				continue
			}
			weight := 1
			if group.Weight != nil {
				weight = int(*group.Weight)
			}
			groups = append(groups, WeightedTargetGroup{ARN: string(*group.TargetGroupArn), Weight: weight})
		}
		return groups
	}
	if action.TargetGroupArn != nil {
		return []WeightedTargetGroup{{ARN: string(*action.TargetGroupArn), Weight: 1}}
	}
	return nil
}

// SelectAction resolves the terminal action and weighted group using draw modulo
// total weight. It never mutates the configuration or fails over between groups.
// A selected forward action contains only the chosen TargetGroupArn.
func SelectAction(actions api.Actions, draw uint64) (api.Action, error) {
	if err := validateActionShapes(actions); err != nil {
		return api.Action{}, err
	}
	action := actions[0]
	if *action.Type != api.ActionTypeEnumFORWARD || action.ForwardConfig == nil {
		return action, nil
	}
	groups := action.ForwardConfig.TargetGroups
	total := 0
	for _, group := range groups {
		if group.Weight == nil {
			total++
		} else {
			total += int(*group.Weight)
		}
	}
	if total == 0 {
		return api.Action{}, fmt.Errorf("forward action has no positive-weight target group")
	}
	position := int(draw % uint64(total))
	for _, group := range groups {
		weight := 1
		if group.Weight != nil {
			weight = int(*group.Weight)
		}
		if position < weight {
			action.TargetGroupArn, action.ForwardConfig = group.TargetGroupArn, nil
			return action, nil
		}
		position -= weight
	}
	return api.Action{}, fmt.Errorf("forward action has no selectable target group")
}

// RedirectURL interpolates AWS redirect keywords using the original URL (not
// forwarded headers). It rejects protocol downgrades and request-specific loops.
func RedirectURL(action api.Action, r *http.Request) (string, int, error) {
	if action.Type == nil || *action.Type != api.ActionTypeEnumREDIRECT || action.RedirectConfig == nil {
		return "", 0, fmt.Errorf("redirect configuration is required")
	}
	c := action.RedirectConfig
	if err := validateRedirect(c); err != nil {
		return "", 0, err
	}
	if r == nil || r.URL == nil {
		return "", 0, fmt.Errorf("redirect request URL is required")
	}
	scheme := strings.ToLower(r.URL.Scheme)
	if r.TLS != nil {
		scheme = "https"
	}
	if scheme == "" {
		scheme = "http"
	}
	if scheme != "http" && scheme != "https" {
		return "", 0, fmt.Errorf("redirect requires an HTTP or HTTPS request")
	}
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	original := &url.URL{Scheme: scheme, Host: authority}
	host, port := original.Hostname(), original.Port()
	if host == "" {
		return "", 0, fmt.Errorf("redirect request host is required")
	}
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	originalPath := r.URL.EscapedPath()
	if originalPath == "" {
		originalPath = "/"
	}
	replace := strings.NewReplacer("#{protocol}", scheme, "#{host}", host, "#{port}", port, "#{path}", strings.TrimPrefix(originalPath, "/"), "#{query}", r.URL.RawQuery)
	newScheme, newHost, newPort, newPath, query := scheme, host, port, originalPath, r.URL.RawQuery
	if c.Protocol != nil {
		newScheme = strings.ToLower(replace.Replace(string(*c.Protocol)))
	}
	if c.Host != nil {
		newHost = replace.Replace(string(*c.Host))
	}
	if c.Port != nil {
		newPort = replace.Replace(string(*c.Port))
	}
	if c.Path != nil {
		newPath = replace.Replace(string(*c.Path))
	}
	if c.Query != nil {
		query = replace.Replace(string(*c.Query))
	}
	if scheme == "https" && newScheme == "http" {
		return "", 0, fmt.Errorf("HTTPS to HTTP redirects are not supported")
	}
	if strings.EqualFold(newScheme, scheme) && strings.EqualFold(newHost, host) && newPort == port && newPath == originalPath {
		return "", 0, fmt.Errorf("redirect would loop: protocol, host, port and path are unchanged")
	}
	decoded, err := url.PathUnescape(newPath)
	if err != nil {
		return "", 0, fmt.Errorf("invalid redirect path: %w", err)
	}
	query = strings.NewReplacer(" ", "%20", "#", "%23").Replace(query)
	target := &url.URL{Scheme: newScheme, Host: net.JoinHostPort(newHost, newPort), Path: decoded, RawPath: newPath, RawQuery: query}
	status := http.StatusMovedPermanently
	if *c.StatusCode == api.RedirectActionStatusCodeEnumHTTP_302 {
		status = http.StatusFound
	}
	return target.String(), status, nil
}

// FixedResponse returns a validated response. Omitted content type is text/plain.
func FixedResponse(action api.Action) (status int, contentType string, body string, err error) {
	if action.Type == nil || *action.Type != api.ActionTypeEnumFIXED_RESPONSE || action.FixedResponseConfig == nil {
		return 0, "", "", fmt.Errorf("fixed-response configuration is required")
	}
	c := action.FixedResponseConfig
	if c.StatusCode == nil {
		return 0, "", "", fmt.Errorf("fixed-response status code is required")
	}
	code := string(*c.StatusCode)
	status, err = strconv.Atoi(code)
	if err != nil || len(code) != 3 || !(status >= 200 && status <= 299 || status >= 400 && status <= 599) {
		return 0, "", "", fmt.Errorf("fixed-response status must be 2XX, 4XX, or 5XX")
	}
	contentType = "text/plain"
	if c.ContentType != nil {
		contentType = string(*c.ContentType)
	}
	switch contentType {
	case "text/plain", "text/css", "text/html", "application/javascript", "application/json":
	default:
		return 0, "", "", fmt.Errorf("unsupported fixed-response content type %q", contentType)
	}
	if c.MessageBody != nil {
		body = string(*c.MessageBody)
	}
	if utf8.RuneCountInString(body) > 1024 {
		return 0, "", "", fmt.Errorf("fixed-response body exceeds 1024 characters")
	}
	return status, contentType, body, nil
}
