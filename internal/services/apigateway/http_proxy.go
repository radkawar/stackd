package apigateway

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigatewayexec"
)

var httpProxyParameterName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func validatePathDeclarations(resource ResourceRecord, parameters map[string]bool) error {
	for name := range parameters {
		part := strings.TrimPrefix(name, "method.request.path.")
		if part == name || !httpProxyParameterName.MatchString(part) {
			return unsupported("only declared method path parameters are supported")
		}
		if !strings.Contains(resource.Path, "{"+part+"}") && !strings.Contains(resource.Path, "{"+part+"+}") {
			return bad("Method path parameter is absent from resource path")
		}
	}
	return nil
}

func validateHTTPProxy(in *apigatewayexec.HTTPProxyIntegration, method MethodRecord, resource ResourceRecord) error {
	if !methodVerb(in.Method) {
		return bad("Invalid HTTP proxy integration method")
	}
	if strings.ContainsAny(in.URI, " \t\r\n\\") || strings.Contains(in.URI, "${") {
		return bad("HTTP proxy URI must be encoded; stage substitutions are unsupported")
	}
	for _, c := range in.URI {
		if c < 33 || c > 126 {
			return bad("HTTP proxy URI must be ASCII and percent-encoded")
		}
	}
	// Validate placeholders separately so substitutions cannot alter authority.
	schemeEnd := strings.Index(in.URI, "://")
	if schemeEnd < 0 {
		return bad("HTTP proxy URI requires http or https")
	}
	pathStart := strings.IndexByte(in.URI[schemeEnd+3:], '/')
	authorityEnd := len(in.URI)
	if pathStart >= 0 {
		authorityEnd = schemeEnd + 3 + pathStart
	}
	if strings.ContainsAny(in.URI[:authorityEnd], "{}") {
		return unsupported("HTTP proxy authority substitutions")
	}
	u, err := url.Parse(in.URI)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || strings.Contains(in.URI, "#") || u.Opaque != "" || strings.HasSuffix(u.Host, ":") || strings.ContainsAny(u.RawQuery, "{}") {
		return bad("Invalid HTTP proxy endpoint URI")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 || (port <= 1024 && port != 80 && port != 443) {
			return bad("HTTP proxy endpoint requires port 80, 443 or above 1024")
		}
	}
	if net.ParseIP(u.Hostname()) == nil {
		// Native DNS and localhost are routable endpoints in the local network
		// namespace; they do not imply or emulate an AWS VPC_LINK.
		for _, label := range strings.Split(strings.TrimSuffix(u.Hostname(), "."), ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return bad("Invalid HTTP proxy hostname")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return bad("Invalid HTTP proxy hostname")
				}
			}
		}
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return bad("Invalid HTTP proxy endpoint query")
	}
	placeholders := map[string]bool{}
	for _, segment := range strings.Split(u.Path, "/") {
		if strings.ContainsAny(segment, "{}") {
			name := strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
			if segment != "{"+name+"}" || !httpProxyParameterName.MatchString(name) || !strings.Contains(in.URI, "/{"+name+"}") {
				return unsupported("HTTP proxy placeholders must be complete path segments")
			}
			placeholders[name] = true
		}
	}
	for target, source := range in.PathParameters {
		if !placeholders[target] || !httpProxyParameterName.MatchString(source) {
			return bad("Invalid HTTP proxy path parameter mapping")
		}
		if _, ok := method.RequestParameters["method.request.path."+source]; !ok {
			return bad("HTTP proxy mapping requires a declared method path parameter")
		}
	}
	for target := range placeholders {
		if _, ok := in.PathParameters[target]; !ok {
			return bad("HTTP proxy URI path placeholder requires a request parameter mapping")
		}
	}
	return validatePathDeclarations(resource, method.RequestParameters)
}

func (s *Service) putHTTPProxy(tx Transaction, key MethodKey, method MethodRecord, in *api.PutIntegrationRequest) (*api.Integration, error) {
	if value(in.Credentials) != "" || len(in.CacheKeyParameters) != 0 || len(in.RequestTemplates) != 0 || value(in.ContentHandling) != "" || value(in.ConnectionId) != "" || value(in.IntegrationTarget) != "" || in.TlsConfig != nil {
		return nil, unsupported("HTTP proxy credentials, caching, templates, conversion, private integration or TLS settings")
	}
	if v := value(in.ConnectionType); v != "" && v != "INTERNET" {
		return nil, unsupported("HTTP proxy private integration")
	}
	if v := value(in.PassthroughBehavior); v != "" && v != "WHEN_NO_MATCH" {
		return nil, unsupported("HTTP proxy passthrough behavior")
	}
	if v := value(in.ResponseTransferMode); v != "" && v != "BUFFERED" {
		return nil, unsupported("HTTP proxy streaming integration")
	}
	if v := value(in.CacheNamespace); v != "" && v != key.ResourceID {
		return nil, unsupported("HTTP proxy custom cache namespace")
	}
	timeout := int32(29000)
	if in.TimeoutInMillis != nil {
		timeout = int32(*in.TimeoutInMillis)
	}
	if timeout < 50 || timeout > 29000 {
		return nil, bad("HTTP proxy timeout must be between 50 and 29000 milliseconds")
	}
	proxy := &apigatewayexec.HTTPProxyIntegration{URI: value(in.Uri), Method: value(in.IntegrationHttpMethod), PathParameters: map[string]string{}}
	for target, source := range in.RequestParameters {
		name := strings.TrimPrefix(string(target), "integration.request.path.")
		parameter := strings.TrimPrefix(string(source), "method.request.path.")
		if name == string(target) || parameter == string(source) {
			return nil, unsupported("HTTP proxy supports only method path to integration path mappings")
		}
		proxy.PathParameters[name] = parameter
	}
	resource, err := tx.Resource(key.ResourceKey)
	if err != nil {
		return nil, err
	}
	if err := validateHTTPProxy(proxy, method, resource); err != nil {
		return nil, err
	}
	row := IntegrationRecord{Key: key, URI: proxy.URI, TimeoutMillis: timeout, HTTPProxy: proxy}
	if err := tx.PutIntegration(row); err != nil {
		return nil, err
	}
	return integrationOutput(row), nil
}

func patchHTTPProxy(p api.PatchOperation, row *IntegrationRecord) error {
	if p.From != nil {
		return bad("Unsupported HTTP proxy patch operation")
	}
	switch value(p.Path) {
	case "/uri":
		if err := replace(p, &row.URI); err != nil {
			return err
		}
		row.HTTPProxy.URI = row.URI
	case "/httpMethod":
		return replace(p, &row.HTTPProxy.Method)
	case "/timeoutInMillis":
		v := strconv.Itoa(int(row.TimeoutMillis))
		if err := replace(p, &v); err != nil {
			return err
		}
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 50 || n > 29000 {
			return bad("HTTP proxy timeout must be between 50 and 29000 milliseconds")
		}
		row.TimeoutMillis = int32(n)
	case "/passthroughBehavior":
		v := "WHEN_NO_MATCH"
		if err := replace(p, &v); err != nil {
			return err
		}
		if v != "WHEN_NO_MATCH" {
			return unsupported("HTTP proxy passthrough behavior")
		}
	case "/responseTransferMode":
		v := "BUFFERED"
		if err := replace(p, &v); err != nil {
			return err
		}
		if v != "BUFFERED" {
			return unsupported("HTTP proxy streaming integration")
		}
	default:
		prefix := "/requestParameters/integration.request.path."
		if !strings.HasPrefix(value(p.Path), prefix) {
			return unsupported("HTTP proxy integration patch path " + value(p.Path))
		}
		name := strings.TrimPrefix(value(p.Path), prefix)
		switch value(p.Op) {
		case "remove":
			if _, ok := row.HTTPProxy.PathParameters[name]; !ok {
				return bad("HTTP proxy request parameter does not exist")
			}
			delete(row.HTTPProxy.PathParameters, name)
		case "add", "replace":
			if p.Value == nil {
				return bad("HTTP proxy request parameter patch value is required")
			}
			source := strings.TrimPrefix(value(p.Value), "method.request.path.")
			if source == value(p.Value) {
				return unsupported("HTTP proxy supports only method path mappings")
			}
			if row.HTTPProxy.PathParameters == nil {
				row.HTTPProxy.PathParameters = map[string]string{}
			}
			row.HTTPProxy.PathParameters[name] = source
		default:
			return unsupported("HTTP proxy request parameter patch operation")
		}
	}
	return nil
}
