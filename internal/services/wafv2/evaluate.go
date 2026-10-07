package wafv2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/wafv2"
)

// HTTPRequest is a web request as received by the protected resource.
type HTTPRequest struct {
	Method, URI, RawQuery, HTTPVersion, SourceIP string
	// Header includes Host. Names are matched case-insensitively.
	Header http.Header
	Body   []byte
}

// Verdict is the web ACL's disposition of one request.
type Verdict struct {
	Blocked bool
	// Custom reports a Block CustomResponse; otherwise the protected resource
	// sends its own WAF block response (API Gateway's WAF_FILTERED, 403).
	Custom      bool
	Status      int
	Headers     http.Header
	Body        []byte
	ContentType string
	// InsertHeaders are added to the request forwarded to the protected resource.
	InsertHeaders http.Header
}

// Header and cookie inspection limits for all-header and cookie components.
const (
	maxInspectedEntries = 200
	maxInspectedBytes   = 8192
	defaultBodyLimit    = 16 * 1024
)

type evaluation struct {
	s        *Service
	acl      WebACL
	ipSets   map[string][]netip.Prefix
	req      *HTTPRequest
	now      time.Time
	labels   []string
	inserted http.Header
}

type outcome struct {
	action   string // ALLOW or BLOCK
	rule     *api.Rule
	counted  []*api.Rule
	response *api.CustomResponse
}

// InspectRESTStage evaluates the web ACL associated with an API Gateway REST
// stage. A stage without a live association is not filtered.
func (s *Service) InspectRESTStage(ctx context.Context, sc Scope, apiID, stage string, req *HTTPRequest) (Verdict, error) {
	resource := RESTStageARN(sc, apiID, stage)
	var assoc Association
	var acl WebACL
	ipSets := map[string][]netip.Prefix{}
	found := false
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		assoc, err = r.Association(sc, resource)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if acl, err = r.WebACL(sc, assoc.WebACLARN); err != nil {
			return err
		}
		for _, arn := range definitionIPSets(acl.Definition) {
			set, err := r.IPSet(sc, arn)
			if err != nil {
				return err
			}
			prefixes := make([]netip.Prefix, 0, len(set.Addresses))
			for _, a := range set.Addresses {
				if p, err := netip.ParsePrefix(a); err == nil {
					prefixes = append(prefixes, p.Masked())
				}
			}
			ipSets[arn] = prefixes
		}
		found = true
		return nil
	})
	if err != nil || !found {
		return Verdict{}, err
	}
	if live, err := s.live(ctx, assoc); err != nil || !live {
		return Verdict{}, err
	}
	e := &evaluation{s: s, acl: acl, ipSets: ipSets, req: req, now: s.clock.Now().UTC(), inserted: http.Header{}}
	result := e.run()
	verdict := Verdict{Blocked: result.action == "BLOCK"}
	if verdict.Blocked {
		if r := result.response; r != nil {
			verdict.Custom, verdict.Status, verdict.Headers = true, int(*r.ResponseCode), http.Header{}
			for _, h := range r.ResponseHeaders {
				verdict.Headers.Add(value(h.Name), value(h.Value))
			}
			if key := value(r.CustomResponseBodyKey); key != "" {
				body := acl.Definition.CustomResponseBodies[api.EntityName(key)]
				verdict.Body = []byte(value(body.Content))
				verdict.ContentType = map[string]string{"TEXT_PLAIN": "text/plain", "TEXT_HTML": "text/html", "APPLICATION_JSON": "application/json"}[value(body.ContentType)]
			}
		}
	} else {
		verdict.InsertHeaders = e.inserted
	}
	if err := s.observe(ctx, e, result, verdict); err != nil {
		return Verdict{}, err
	}
	return verdict, nil
}

func (e *evaluation) run() outcome {
	rules := make([]*api.Rule, 0, len(e.acl.Definition.Rules))
	for i := range e.acl.Definition.Rules {
		rules = append(rules, &e.acl.Definition.Rules[i])
	}
	slices.SortFunc(rules, func(a, b *api.Rule) int { return int(*a.Priority) - int(*b.Priority) })
	var counted []*api.Rule
	for _, rule := range rules {
		if !e.statement(rule.Statement, rule) {
			continue
		}
		for _, label := range rule.RuleLabels {
			e.labels = append(e.labels, e.acl.LabelNamespace()+value(label.Name))
		}
		switch a := rule.Action; {
		case a.Count != nil:
			e.insert(a.Count.CustomRequestHandling)
			counted = append(counted, rule)
		case a.Allow != nil:
			e.insert(a.Allow.CustomRequestHandling)
			return outcome{action: "ALLOW", rule: rule, counted: counted}
		default:
			return outcome{action: "BLOCK", rule: rule, counted: counted, response: a.Block.CustomResponse}
		}
	}
	d := e.acl.Definition.DefaultAction
	if d.Allow != nil {
		e.insert(d.Allow.CustomRequestHandling)
		return outcome{action: "ALLOW", counted: counted}
	}
	return outcome{action: "BLOCK", counted: counted, response: d.Block.CustomResponse}
}

// insert records custom request headers; AWS WAF prefixes names with x-amzn-waf-.
func (e *evaluation) insert(v *api.CustomRequestHandling) {
	if v == nil {
		return
	}
	for _, h := range v.InsertHeaders {
		e.inserted.Set("x-amzn-waf-"+value(h.Name), value(h.Value))
	}
}

func (e *evaluation) statement(s *api.Statement, rule *api.Rule) bool {
	switch {
	case s.AndStatement != nil:
		for i := range s.AndStatement.Statements {
			if !e.statement(&s.AndStatement.Statements[i], rule) {
				return false
			}
		}
		return true
	case s.OrStatement != nil:
		for i := range s.OrStatement.Statements {
			if e.statement(&s.OrStatement.Statements[i], rule) {
				return true
			}
		}
		return false
	case s.NotStatement != nil:
		return !e.statement(s.NotStatement.Statement, rule)
	case s.ByteMatchStatement != nil:
		v := s.ByteMatchStatement
		return e.inspect(v.FieldToMatch, v.TextTransformations, func(b []byte) bool {
			return byteMatch(b, v.SearchString, value(v.PositionalConstraint))
		})
	case s.RegexMatchStatement != nil:
		v := s.RegexMatchStatement
		pattern := e.s.regex(value(v.RegexString))
		return e.inspect(v.FieldToMatch, v.TextTransformations, pattern.Match)
	case s.SizeConstraintStatement != nil:
		v := s.SizeConstraintStatement
		return e.inspect(v.FieldToMatch, v.TextTransformations, func(b []byte) bool {
			return compareSize(int64(len(b)), int64(*v.Size), value(v.ComparisonOperator))
		})
	case s.IPSetReferenceStatement != nil:
		return e.ipSetMatch(s.IPSetReferenceStatement)
	case s.LabelMatchStatement != nil:
		return e.labelMatch(value(s.LabelMatchStatement.Key), value(s.LabelMatchStatement.Scope))
	case s.RateBasedStatement != nil:
		return e.rateBased(s.RateBasedStatement, rule)
	}
	return false
}

func (s *Service) regex(pattern string) *regexp.Regexp {
	if v, ok := s.patterns.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	compiled := regexp.MustCompile(pattern) // validated at admission
	s.patterns.Store(pattern, compiled)
	return compiled
}

func wordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func byteMatch(component, search []byte, constraint string) bool {
	switch constraint {
	case "EXACTLY":
		return bytes.Equal(component, search)
	case "STARTS_WITH":
		return bytes.HasPrefix(component, search)
	case "ENDS_WITH":
		return bytes.HasSuffix(component, search)
	case "CONTAINS":
		return bytes.Contains(component, search)
	default: // CONTAINS_WORD
		for offset := 0; offset <= len(component)-len(search); {
			i := bytes.Index(component[offset:], search)
			if i < 0 {
				return false
			}
			start, end := offset+i, offset+i+len(search)
			if (start == 0 || !wordByte(component[start-1])) && (end == len(component) || !wordByte(component[end])) {
				return true
			}
			offset = start + 1
		}
		return false
	}
}

func compareSize(size, limit int64, op string) bool {
	switch op {
	case "EQ":
		return size == limit
	case "NE":
		return size != limit
	case "LE":
		return size <= limit
	case "LT":
		return size < limit
	case "GE":
		return size >= limit
	default:
		return size > limit
	}
}

// inspect evaluates transformed component values; any matching value matches.
func (e *evaluation) inspect(f *api.FieldToMatch, tt api.TextTransformations, match func([]byte) bool) bool {
	values, decided := e.component(f)
	if decided != nil {
		return *decided
	}
	for _, v := range values {
		if match(transform(v, tt)) {
			return true
		}
	}
	return false
}

func decided(v bool) *bool { return &v }

func oversized(h *api.OversizeHandling) *bool {
	switch value(h) {
	case "MATCH":
		return decided(true)
	case "NO_MATCH":
		return decided(false)
	}
	return nil
}

func fallback(v *api.FallbackBehavior) *bool { return decided(value(v) == "MATCH") }

func (e *evaluation) bodyLimit() int {
	if c := e.acl.Definition.AssociationConfig; c != nil {
		if v, ok := c.RequestBody["API_GATEWAY"]; ok {
			switch value(v.DefaultSizeInspectionLimit) {
			case "KB_32":
				return 32 * 1024
			case "KB_48":
				return 48 * 1024
			case "KB_64":
				return 64 * 1024
			}
		}
	}
	return defaultBodyLimit
}

func (e *evaluation) header(name string) []string {
	var out []string
	for k, vs := range e.req.Header {
		if strings.EqualFold(strings.TrimSpace(k), name) {
			out = append(out, vs...)
		}
	}
	return out
}

type queryArg struct{ name, value string }

func (e *evaluation) query() []queryArg {
	var out []queryArg
	for _, part := range strings.Split(e.req.RawQuery, "&") {
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		out = append(out, queryArg{string(urlDecode([]byte(name), false)), val})
	}
	return out
}

// component extracts a request component per the AWS WAF request component
// rules. A non-nil decision short-circuits inspection (oversize or fallback).
func (e *evaluation) component(f *api.FieldToMatch) ([][]byte, *bool) {
	switch {
	case f.Method != nil:
		return [][]byte{[]byte(e.req.Method)}, nil
	case f.UriPath != nil:
		return [][]byte{[]byte(e.req.URI)}, nil
	case f.QueryString != nil:
		if e.req.RawQuery == "" {
			return nil, nil
		}
		return [][]byte{[]byte(e.req.RawQuery)}, nil
	case f.SingleHeader != nil:
		var out [][]byte
		for _, v := range e.header(strings.TrimSpace(value(f.SingleHeader.Name))) {
			out = append(out, []byte(v))
		}
		return out, nil
	case f.SingleQueryArgument != nil:
		var out [][]byte
		for _, arg := range e.query() {
			if strings.EqualFold(arg.name, value(f.SingleQueryArgument.Name)) {
				out = append(out, []byte(arg.value))
			}
		}
		return out, nil
	case f.AllQueryArguments != nil:
		var out [][]byte
		for _, arg := range e.query() {
			out = append(out, []byte(arg.value))
		}
		return out, nil
	case f.Body != nil:
		body, d := e.body(f.Body.OversizeHandling)
		if d != nil || len(body) == 0 {
			return nil, d
		}
		return [][]byte{body}, nil
	case f.JsonBody != nil:
		return e.jsonBody(f.JsonBody)
	case f.Headers != nil:
		return e.mapComponent(e.headerEntries(), f.Headers.MatchPattern.All != nil, f.Headers.MatchPattern.IncludedHeaders, f.Headers.MatchPattern.ExcludedHeaders, false, value(f.Headers.MatchScope), f.Headers.OversizeHandling)
	case f.Cookies != nil:
		p := f.Cookies.MatchPattern
		included := make(api.HeaderNames, 0, len(p.IncludedCookies))
		for _, c := range p.IncludedCookies {
			included = append(included, api.FieldToMatchData(c))
		}
		excluded := make(api.HeaderNames, 0, len(p.ExcludedCookies))
		for _, c := range p.ExcludedCookies {
			excluded = append(excluded, api.FieldToMatchData(c))
		}
		return e.mapComponent(e.cookieEntries(), p.All != nil, included, excluded, true, value(f.Cookies.MatchScope), f.Cookies.OversizeHandling)
	case f.UriFragment != nil:
		// Fragments are never sent to API Gateway; AWS WAF applies the fallback.
		return nil, fallback(f.UriFragment.FallbackBehavior)
	case f.JA3Fingerprint != nil:
		// JA3 is calculated only for CloudFront and Application Load Balancers.
		return nil, fallback(f.JA3Fingerprint.FallbackBehavior)
	case f.JA4Fingerprint != nil:
		return nil, fallback(f.JA4Fingerprint.FallbackBehavior)
	}
	return nil, decided(false)
}

func (e *evaluation) body(h *api.OversizeHandling) ([]byte, *bool) {
	body, limit := e.req.Body, e.bodyLimit()
	if len(body) > limit {
		if d := oversized(h); d != nil {
			return nil, d
		}
		body = body[:limit]
	}
	return body, nil
}

type entry struct{ key, value string }

func (e *evaluation) headerEntries() []entry {
	names := make([]string, 0, len(e.req.Header))
	for k := range e.req.Header {
		names = append(names, k)
	}
	slices.Sort(names)
	var out []entry
	for _, k := range names {
		for _, v := range e.req.Header[k] {
			out = append(out, entry{strings.ToLower(k), v})
		}
	}
	return out
}

func (e *evaluation) cookieEntries() []entry {
	var out []entry
	for _, line := range e.header("cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			k, v, _ := strings.Cut(part, "=")
			out = append(out, entry{k, v})
		}
	}
	return out
}

// mapComponent applies match pattern, scope and size limits to header or
// cookie entries. Header keys compare case-insensitively; cookie keys exactly.
func (e *evaluation) mapComponent(entries []entry, all bool, included, excluded api.HeaderNames, exact bool, scope string, h *api.OversizeHandling) ([][]byte, *bool) {
	size := 0
	for _, x := range entries {
		size += len(x.key) + len(x.value)
	}
	if len(entries) > maxInspectedEntries || size > maxInspectedBytes {
		if d := oversized(h); d != nil {
			return nil, d
		}
		limited, used := entries[:0:0], 0
		for _, x := range entries {
			if len(limited) == maxInspectedEntries || used+len(x.key)+len(x.value) > maxInspectedBytes {
				break
			}
			used += len(x.key) + len(x.value)
			limited = append(limited, x)
		}
		entries = limited
	}
	matches := func(list api.HeaderNames, key string) bool {
		for _, candidate := range list {
			c := strings.TrimSpace(string(candidate))
			if exact && c == key || !exact && strings.EqualFold(c, strings.TrimSpace(key)) {
				return true
			}
		}
		return false
	}
	var out [][]byte
	for _, x := range entries {
		if !all && (len(included) > 0 && !matches(included, x.key) || len(excluded) > 0 && matches(excluded, x.key)) {
			continue
		}
		if scope != "VALUE" {
			out = append(out, []byte(x.key))
		}
		if scope != "KEY" {
			out = append(out, []byte(x.value))
		}
	}
	return out, nil
}

// jsonBody extracts JSON elements following the documented JsonBody steps:
// parse, select by match scope and included paths, then inspect.
func (e *evaluation) jsonBody(v *api.JsonBody) ([][]byte, *bool) {
	body, d := e.body(v.OversizeHandling)
	if d != nil {
		return nil, d
	}
	if len(body) == 0 {
		return nil, nil
	}
	scope := value(v.MatchScope)
	var included []string
	if v.MatchPattern.All == nil {
		for _, p := range v.MatchPattern.IncludedPaths {
			included = append(included, string(p))
		}
	}
	selected := func(path string, strict bool) bool {
		if included == nil {
			return true
		}
		for _, p := range included {
			if p == "" || strings.HasPrefix(path, p+"/") || !strict && path == p {
				return true
			}
		}
		return false
	}
	values, err := jsonElements(body, func(path string, key bool) bool {
		if key {
			return scope != "VALUE" && selected(path, true)
		}
		return scope != "KEY" && selected(path, false)
	})
	if err != nil {
		switch value(v.InvalidFallbackBehavior) {
		case "MATCH":
			return nil, decided(true)
		case "NO_MATCH":
			return nil, decided(false)
		case "EVALUATE_AS_STRING":
			return [][]byte{body}, nil
		}
	}
	return values, nil
}

type jsonFrame struct {
	object bool
	index  int
	key    string
	keyed  bool
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// jsonElements streams JSON tokens, returning the selected keys and scalar
// values collected up to the first parse error, if any.
func jsonElements(body []byte, want func(path string, key bool) bool) ([][]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var stack []jsonFrame
	var out [][]byte
	path := func() string {
		var b strings.Builder
		for _, f := range stack {
			b.WriteByte('/')
			if f.object {
				b.WriteString(escapePointer(f.key))
			} else {
				b.WriteString(strconv.Itoa(f.index - 1))
			}
		}
		return b.String()
	}
	advance := func() {
		if n := len(stack); n > 0 {
			if stack[n-1].object {
				stack[n-1].keyed = false
			}
		}
	}
	first := true
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if len(stack) > 0 {
				return out, io.ErrUnexpectedEOF
			}
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if first {
			if d, ok := tok.(json.Delim); !ok || d != '{' && d != '[' {
				return out, errors.New("JSON root must be an object or array")
			}
			first = false
		}
		// Object keys arrive as strings when the enclosing object awaits a key.
		if n := len(stack); n > 0 && stack[n-1].object && !stack[n-1].keyed {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:n-1]
				advance()
				continue
			}
			key, _ := tok.(string)
			stack[n-1].key, stack[n-1].keyed = key, true
			if want(path(), true) {
				out = append(out, []byte(key))
			}
			continue
		}
		if n := len(stack); n > 0 && !stack[n-1].object {
			if d, ok := tok.(json.Delim); !ok || d != ']' {
				stack[n-1].index++
			}
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, jsonFrame{object: true})
			case '[':
				stack = append(stack, jsonFrame{})
			default:
				stack = stack[:len(stack)-1]
				advance()
			}
		default:
			if want(path(), false) {
				var text string
				switch v := t.(type) {
				case string:
					text = v
				case json.Number:
					text = v.String()
				case bool:
					text = strconv.FormatBool(v)
				default:
					text = "null"
				}
				out = append(out, []byte(text))
			}
			advance()
		}
	}
}

// clientIPs returns the inspected address list: the origin or a forwarded
// header. present is false when the forwarded header is absent; valid is false
// when the header is malformed.
func (e *evaluation) clientIPs(header *api.ForwardedIPHeaderName) (ips []netip.Addr, present, valid bool) {
	if header == nil {
		addr, err := netip.ParseAddr(e.req.SourceIP)
		return []netip.Addr{addr.Unmap()}, true, err == nil
	}
	values := e.header(value(header))
	if len(values) == 0 {
		return nil, false, false
	}
	for _, part := range strings.Split(strings.Join(values, ","), ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return nil, true, false
		}
		ips = append(ips, addr.Unmap())
	}
	return ips, true, true
}

func (e *evaluation) ipSetMatch(v *api.IPSetReferenceStatement) bool {
	var header *api.ForwardedIPHeaderName
	position := "FIRST"
	var fb *api.FallbackBehavior
	if f := v.IPSetForwardedIPConfig; f != nil {
		header, position, fb = f.HeaderName, value(f.Position), f.FallbackBehavior
	}
	ips, present, valid := e.clientIPs(header)
	if !present {
		return false
	}
	if !valid {
		return *fallback(fb)
	}
	switch position {
	case "LAST":
		ips = ips[len(ips)-1:]
	case "ANY":
		ips = ips[max(0, len(ips)-10):]
	default:
		ips = ips[:1]
	}
	for _, ip := range ips {
		for _, p := range e.ipSets[value(v.ARN)] {
			if p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// labelMatch implements local and fully qualified label and namespace keys.
func (e *evaluation) labelMatch(key, scope string) bool {
	local := e.acl.LabelNamespace()
	qualified := strings.HasPrefix(key, "awswaf:")
	for _, label := range e.labels {
		switch {
		case scope == "LABEL" && qualified:
			if label == key {
				return true
			}
		case scope == "LABEL":
			if rest, ok := strings.CutPrefix(label, local); ok && (rest == key || strings.HasSuffix(rest, ":"+key)) {
				return true
			}
		case qualified:
			if strings.HasPrefix(label, key) {
				return true
			}
		default:
			if rest, ok := strings.CutPrefix(label, local); ok && strings.Contains(":"+rest, ":"+key) {
				return true
			}
		}
	}
	return false
}

func (e *evaluation) rateBased(v *api.RateBasedStatement, rule *api.Rule) bool {
	if v.ScopeDownStatement != nil && !e.statement(v.ScopeDownStatement, rule) {
		return false
	}
	key := ""
	switch value(v.AggregateKeyType) {
	case "IP", "FORWARDED_IP":
		var header *api.ForwardedIPHeaderName
		var fb *api.FallbackBehavior
		if f := v.ForwardedIPConfig; f != nil {
			header, fb = f.HeaderName, f.FallbackBehavior
		}
		ips, present, valid := e.clientIPs(header)
		if !present {
			return false
		}
		if !valid {
			return *fallback(fb)
		}
		key = ips[0].String()
	}
	window := 300 * time.Second
	if v.EvaluationWindowSec != nil {
		window = time.Duration(*v.EvaluationWindowSec) * time.Second
	}
	config, _ := json.Marshal(v)
	return e.s.rates.observe(rateKey{e.acl.ARN, value(rule.Name), string(config), key}, e.now, window, int64(*v.Limit))
}
