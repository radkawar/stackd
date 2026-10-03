package opensearch

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const DataPrefix = "/_stackd/opensearch/"

func domainPath(v Domain) string {
	return DataPrefix + v.Key.Partition + "/" + v.Key.AccountID + "/" + v.Key.Region + "/" + v.Key.Name + "/" + v.Incarnation
}
func dataPath(path string) (Key, string, string, bool) {
	if !strings.HasPrefix(path, DataPrefix) {
		return Key{}, "", "", false
	}
	pieces := strings.SplitN(strings.TrimPrefix(path, DataPrefix), "/", 6)
	if len(pieces) < 5 || pieces[0] == "" || len(pieces[1]) != 12 || pieces[2] == "" || !domainName.MatchString(pieces[3]) || pieces[4] == "" {
		return Key{}, "", "", false
	}
	native := "/"
	if len(pieces) == 6 {
		native += pieces[5]
	}
	return Key{Scope{pieces[0], pieces[1], pieces[2]}, pieces[3]}, pieces[4], native, true
}

// DataPlaneRegion lets the shared gateway select this native endpoint before
// Smithy decoding. That gateway still owns SigV4, bounded bodies and transport
// metadata; an unsigned request obtains no implicit account-root authority.
func (s *Service) DataPlaneRegion(r *http.Request) (string, bool) {
	if !strings.HasPrefix(r.URL.Path, DataPrefix) {
		return "", false
	}
	k, _, _, ok := dataPath(r.URL.Path)
	if !ok {
		return "", true
	}
	return k.Region, true
}
func boundPolicy(v Domain) authorization.BoundPolicy {
	return authorization.BoundPolicy{Document: v.AccessPolicy, PrincipalIDs: v.PolicyPrincipals}
}
func dataAction(method string) string {
	switch method {
	case "GET":
		return "ESHttpGet"
	case "HEAD":
		return "ESHttpHead"
	case "POST":
		return "ESHttpPost"
	case "PUT":
		return "ESHttpPut"
	case "PATCH":
		return "ESHttpPatch"
	case "DELETE":
		return "ESHttpDelete"
	}
	return ""
}

type nativeTargetKey struct{}
type nativeTarget struct {
	URL           *url.URL
	Path, RawPath string
}

var nativeProxy = &httputil.ReverseProxy{
	Rewrite: func(p *httputil.ProxyRequest) {
		target := p.In.Context().Value(nativeTargetKey{}).(nativeTarget)
		p.SetURL(target.URL)
		p.Out.URL.Path, p.Out.URL.RawPath = target.Path, target.RawPath
		p.Out.Host = target.URL.Host
		p.Out.Header.Del("Authorization")
		p.Out.Header.Del("X-Amz-Security-Token")
		p.Out.Header.Del("X-Amz-Credential")
		query := p.Out.URL.Query()
		for k := range query {
			if strings.HasPrefix(strings.ToLower(k), "x-amz-") {
				query.Del(k)
			}
		}
		p.Out.URL.RawQuery = query.Encode()
	},
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
		awswire.JSONError(w, r, failure("ServiceUnavailableException", "The native OpenSearch engine is unavailable."))
	},
}

func (s *Service) ServeDataPlane(w http.ResponseWriter, r *http.Request) {
	k, incarnation, path, ok := dataPath(r.URL.Path)
	reject := func(e error) { awswire.JSONError(w, r, wireError(e)) }
	if !ok {
		reject(failure("ValidationException", "Invalid OpenSearch endpoint."))
		return
	}
	metadata := awsctx.FromContext(r.Context())
	if metadata.Region != k.Region || metadata.Partition != k.Partition {
		reject(failure("AccessDeniedException", "Endpoint scope does not match the request."))
		return
	}
	action := dataAction(r.Method)
	if action == "" {
		reject(failure("ValidationException", "Unsupported HTTP method."))
		return
	}
	// Never authorize one URI and let the backend normalize it to another.
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			reject(failure("ValidationException", "Dot segments are not supported."))
			return
		}
	}
	// Native PathTrie drops trailing literal separators. Check the escaped URI
	// so an encoded slash in a document ID remains distinct from a separator.
	if path != "/" && strings.HasSuffix(r.URL.EscapedPath(), "/") {
		reject(failure("ValidationException", "Trailing path separators are not supported."))
		return
	}
	var domain Domain
	err := s.repository.View(r.Context(), func(reader Reader) error {
		var err error
		domain, err = reader.Domain(k)
		if err != nil {
			return err
		}
		if domain.Incarnation != incarnation || domain.Status == "deleting" {
			return ErrNotFound
		}
		if err = s.authorize(reader.Context(), action, k.ARN()+path, domain.Tags, nil, &domain); err != nil {
			return err
		}
		if domain.NativeEndpoint == "" {
			return failure("ServiceUnavailableException", "The native OpenSearch engine is not ready.")
		}
		return nil
	})
	if err != nil {
		reject(err)
		return
	}
	if err := nativeAPIAllowed(r.Method, path); err != nil {
		reject(err)
		return
	}
	target, err := url.Parse(domain.NativeEndpoint)
	if err != nil || target.Scheme != "http" || target.Host == "" {
		reject(failure("InternalException", "Invalid native engine endpoint."))
		return
	}
	rawPath := ""
	if r.URL.RawPath != "" {
		prefix := domainPath(domain)
		if !strings.HasPrefix(r.URL.EscapedPath(), prefix) {
			reject(failure("ValidationException", "Encoded domain routing components are not supported."))
			return
		}
		rawPath = strings.TrimPrefix(r.URL.EscapedPath(), prefix)
		if rawPath == "" {
			rawPath = "/"
		}
	}
	ctx := context.WithValue(r.Context(), nativeTargetKey{}, nativeTarget{target, path, rawPath})
	nativeProxy.ServeHTTP(w, r.WithContext(ctx))
}
func nativeAPIAllowed(method, path string) error {
	first := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)[0]
	switch first {
	case "_cluster":
		if method == http.MethodGet && (path == "/_cluster/health" || strings.HasPrefix(path, "/_cluster/health/") || path == "/_cluster/stats") {
			return nil
		}
	case "_nodes":
		if method == http.MethodGet {
			return nil
		}
	case "_snapshot", "_plugins", "_opendistro", "_reindex", "_shutdown":
	default:
		return nil
	}
	// TODO: Comeback expose supported managed administrative APIs, plugins and
	// remote reindex only through their real network/security/dependency owners.
	return failure("ValidationException", "This native administrative API is not supported by the managed domain endpoint.")
}
