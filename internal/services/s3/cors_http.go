package s3

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// ServeCORS handles preflight without authenticating it. For an actual request
// this only adds response headers; resource authorization remains in dispatch.
func (s *Service) ServeCORS(w http.ResponseWriter, r *http.Request, bucket string) bool {
	preflight := r.Method == http.MethodOptions
	origin := r.Header.Get("Origin")
	if origin == "" && !preflight {
		return false
	}
	if preflight {
		var finish func(*http.Request)
		w, r, finish = s.ObserveHTTP(w, r)
		defer func() { finish(r) }()
	}
	writeError := func(wire *awswire.Error) bool {
		if websiteRequest(r) {
			writeWebsiteError(w, r, wire, strings.TrimPrefix(r.URL.Path, "/"), nil, "")
			return true
		}
		model, _ := awscatalog.LookupService("s3")
		awswire.RESTXMLError(w, r, &model, wire)
		return true
	}
	if origin == "" {
		return writeError(failure("BadRequest", "Insufficient information. Origin request header needed.", 400))
	}
	method := r.Header.Get("Access-Control-Request-Method")
	if method == "" {
		method = r.Method
	} else {
		switch method {
		case "GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT":
		default:
			return writeError(failure("BadRequest", "Invalid Access-Control-Request-Method: "+method, 400))
		}
	}
	headers, badHeader := corsRequestedHeaders(r.Header.Get("Access-Control-Request-Headers"))
	if badHeader != "" {
		return writeError(failure("BadRequest", "Access-Control-Request-Headers \""+badHeader+"\" contains invalid character.", 400))
	}
	var rules []CORSRule
	err := s.repository.View(r.Context(), func(reader Reader) error {
		b, point, err := resolveBucketReference(reader, bucket)
		if err != nil {
			return err
		}
		if point != nil && point.VPCID != "" {
			return denied()
		}
		s.captureRequest(reader, b, point)
		rules, err = reader.BucketCORS(b.Key)
		return err
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return writeError(wireError(err))
	}
	for _, rule := range rules {
		if !slices.Contains(rule.AllowedMethods, method) || !corsHeadersMatch(rule.AllowedHeaders, headers) {
			continue
		}
		for _, allowed := range rule.AllowedOrigins {
			if !corsWildcardMatch(allowed, origin) {
				continue
			}
			h := w.Header()
			if allowed == "*" {
				h.Set("Access-Control-Allow-Origin", "*")
			} else {
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
			}
			h.Set("Access-Control-Allow-Methods", strings.Join(rule.AllowedMethods, ", "))
			if len(headers) > 0 {
				h.Set("Access-Control-Allow-Headers", strings.Join(headers, ", "))
			}
			if len(rule.ExposeHeaders) > 0 {
				h.Set("Access-Control-Expose-Headers", strings.Join(rule.ExposeHeaders, ", "))
			}
			if rule.MaxAgeSeconds != nil {
				h.Set("Access-Control-Max-Age", strconv.FormatInt(int64(*rule.MaxAgeSeconds), 10))
			}
			h.Set("Vary", "Origin, Access-Control-Request-Headers, Access-Control-Request-Method")
			if preflight {
				requestID := awsctx.FromContext(r.Context()).RequestID
				h.Set("x-amz-request-id", requestID)
				h.Set("x-amz-id-2", awswire.S3HostID(requestID))
				h.Set("Content-Length", "0")
				w.WriteHeader(http.StatusOK)
			}
			return preflight
		}
	}
	if !preflight {
		return false
	}
	message := "CORSResponse: This CORS request is not allowed. This is usually because the evalution of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec."
	resourceType := "OBJECT"
	path := strings.TrimPrefix(r.URL.Path, "/"+bucket)
	if path == "" || path == "/" {
		resourceType = "BUCKET"
	}
	if errors.Is(err, ErrNotFound) {
		message, resourceType = "CORSResponse: Bucket not found", "BUCKET"
	} else if len(rules) == 0 {
		message, resourceType = "CORSResponse: CORS is not enabled for this bucket.", "BUCKET"
	}
	wire := failure("AccessForbidden", message, http.StatusForbidden)
	wire.Method, wire.ResourceType = method, resourceType
	return writeError(wire)
}

func corsWildcardMatch(pattern, text string) bool {
	prefix, suffix, wildcard := strings.Cut(pattern, "*")
	if !wildcard {
		return pattern == text
	}
	return len(text) >= len(prefix)+len(suffix) && strings.HasPrefix(text, prefix) && strings.HasSuffix(text, suffix)
}

func corsHeadersMatch(allowed, requested []string) bool {
	for _, header := range requested {
		matched := false
		for _, pattern := range allowed {
			if corsWildcardMatch(strings.ToLower(pattern), header) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func corsRequestedHeaders(value string) ([]string, string) {
	if value == "" {
		return nil, ""
	}
	headers := strings.Split(value, ",")
	// Native comma splitting discards trailing empty fields, but a leading
	// empty field participates in rule matching and is echoed in the response.
	for len(headers) > 0 && strings.TrimSpace(headers[len(headers)-1]) == "" {
		headers = headers[:len(headers)-1]
	}
	for i, header := range headers {
		header = strings.TrimSpace(header)
		if !corsHeaderToken(header) {
			return nil, header
		}
		headers[i] = strings.ToLower(header)
	}
	return headers, ""
}

// Empty XML AllowedHeader/ExposeHeader values are admitted by native S3.
func corsHeaderToken(value string) bool {
	for i := range len(value) {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}
