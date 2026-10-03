package awscatalog

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

type httpRoute struct {
	operation             OperationName
	method                string
	path                  *regexp.Regexp
	labels                []string
	rank                  []int
	query                 []httpQueryLiteral
	requiredQuery         []string
	headers               []string
	literals              int
	preserveTrailingSlash bool
}

type httpQueryLiteral struct {
	key, value string
	hasValue   bool
}

// compileHTTPRoutes prepares immutable matchers once, not on each request.
func compileHTTPRoutes(service Service, operations []Operation) []httpRoute {
	var routes []httpRoute
	for _, op := range operations {
		if op.HTTPMethod == "" {
			continue
		}
		path, query, _ := strings.Cut(op.HTTPURI, "?")
		route := httpRoute{operation: op.Name, method: op.HTTPMethod}
		if query != "" {
			for _, literal := range strings.Split(query, "&") {
				key, value, hasValue := strings.Cut(literal, "=")
				key, _ = url.QueryUnescape(key)
				value, _ = url.QueryUnescape(value)
				// S3's client model includes an SDK operation annotation, not
				// a server routing requirement. Raw SigV4 clients omit x-id.
				if service.SigningName == "s3" && key == "x-id" {
					continue
				}
				route.query = append(route.query, httpQueryLiteral{key: key, value: value, hasValue: hasValue})
			}
		}
		route.literals = len(route.query)
		if service.Name == "s3" {
			// S3 distinguishes otherwise identical object routes using modeled
			// required query/header bindings (uploadId, partNumber, copy source).
			shape := service.shapes[op.Input]
			for _, member := range shape.Members {
				if !member.Required {
					continue
				}
				if member.HTTPQuery != "" {
					route.requiredQuery = append(route.requiredQuery, member.HTTPQuery)
				}
				if member.HTTPHeader != "" {
					route.headers = append(route.headers, member.HTTPHeader)
				}
			}
		}
		route.preserveTrailingSlash = service.SigningName == "s3" && strings.HasSuffix(path, "+}")
		var pattern strings.Builder
		pattern.WriteString("^")
		for _, segment := range strings.Split(strings.TrimSuffix(path, "/"), "/")[1:] {
			pattern.WriteByte('/')
			if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
				label := segment[1 : len(segment)-1]
				if strings.HasSuffix(label, "+") {
					label = strings.TrimSuffix(label, "+")
					pattern.WriteString("(.+)")
					route.rank = append(route.rank, 0)
				} else {
					pattern.WriteString("([^/]+)")
					route.rank = append(route.rank, 1)
				}
				route.labels = append(route.labels, label)
			} else {
				pattern.WriteString(regexp.QuoteMeta(segment))
				route.rank = append(route.rank, 2)
			}
		}
		pattern.WriteString("$")
		route.path = regexp.MustCompile(pattern.String())
		slices.SortFunc(route.query, func(a, b httpQueryLiteral) int {
			if n := strings.Compare(a.key, b.key); n != 0 {
				return n
			}
			if n := strings.Compare(a.value, b.value); n != 0 {
				return n
			}
			if a.hasValue == b.hasValue {
				return 0
			}
			if a.hasValue {
				return 1
			}
			return -1
		})
		routes = append(routes, route)
	}
	// A unique literal subresource selects its operation even when required
	// input fields are absent; validation must not fall through to DeleteBucket.
	// Shared subresources retain selectors (for example, configuration GET vs LIST).
	for i, route := range routes {
		if len(route.requiredQuery) == 0 || route.literals == 0 {
			continue
		}
		if !slices.ContainsFunc(routes, func(other httpRoute) bool {
			return other.operation != route.operation && other.method == route.method &&
				other.path.String() == route.path.String() && slices.Equal(other.query, route.query)
		}) {
			routes[i].requiredQuery = nil
		}
	}
	// Required headers discriminate only otherwise identical routes, such as
	// CopyObject and PutObject. A missing attributes header must still select
	// GetObjectAttributes and reach its generated input validation.
	for i, route := range routes {
		if len(route.headers) == 0 {
			continue
		}
		if !slices.ContainsFunc(routes, func(other httpRoute) bool {
			return other.operation != route.operation && other.method == route.method &&
				other.path.String() == route.path.String() && slices.Equal(other.query, route.query) &&
				slices.Equal(other.requiredQuery, route.requiredQuery)
		}) {
			routes[i].headers = nil
		}
	}
	// Smithy path specificity, then literal subresources, then S3's required
	// query/header selectors. Names only make nonambiguous ties stable.
	slices.SortFunc(routes, func(a, b httpRoute) int {
		if n := slices.Compare(b.rank, a.rank); n != 0 {
			return n
		}
		if n := b.literals - a.literals; n != 0 {
			return n
		}
		if n := len(b.query) + len(b.requiredQuery) + len(b.headers) - len(a.query) - len(a.requiredQuery) - len(a.headers); n != 0 {
			return n
		}
		return strings.Compare(string(a.operation), string(b.operation))
	})
	return routes
}

// MatchHTTPOperation matches generated Smithy HTTP bindings. Pass URL.EscapedPath,
// not URL.Path: an encoded slash belongs to one label, and %25 must not be decoded
// twice. S3 additionally selects modeled multipart/copy bindings and preserves
// trailing slashes in object keys; x-id is a client annotation, not a selector.
func (s Service) MatchHTTPOperation(method, escapedPath string, query url.Values, headers http.Header) (Operation, map[string]string, bool) {
	for _, route := range s.httpRoutes {
		if route.method != method {
			continue
		}
		matched := true
		for _, expected := range route.query {
			values, present := query[expected.key]
			if !present || (expected.hasValue && !slices.Contains(values, expected.value)) {
				matched = false
				break
			}
		}
		for _, name := range route.requiredQuery {
			if query.Get(name) == "" {
				matched = false
				break
			}
		}
		for _, name := range route.headers {
			if _, present := headers[http.CanonicalHeaderKey(name)]; !present {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		path := escapedPath
		if !route.preserveTrailingSlash {
			path = strings.TrimSuffix(path, "/")
		}
		matches := route.path.FindStringSubmatch(path)
		if matches == nil {
			continue
		}
		var labels map[string]string
		if len(route.labels) > 0 {
			labels = make(map[string]string, len(route.labels))
		}
		for i, name := range route.labels {
			value, err := url.PathUnescape(matches[i+1])
			if err != nil {
				return Operation{}, nil, false
			}
			labels[name] = value
		}
		op, _ := s.Operation(string(route.operation))
		return op, labels, true
	}
	return Operation{}, nil, false
}
