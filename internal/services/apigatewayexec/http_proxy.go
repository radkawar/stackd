package apigatewayexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPProxyIntegration is the immutable INTERNET REST integration contract.
// PathParameters maps endpoint placeholders to declared method path parameters.
// No host, scheme, query or header substitutions are admitted.
type HTTPProxyIntegration struct {
	URI, Method    string
	PathParameters map[string]string
}

func httpProxyURL(in *HTTPProxyIntegration, parameters map[string]string, rawQuery string) (*url.URL, error) {
	// Substitution is confined to complete path segments by control-plane
	// admission. Escape each segment independently, retaining greedy slashes.
	uri := in.URI
	for target, source := range in.PathParameters {
		value, ok := parameters[source]
		if !ok {
			return nil, fmt.Errorf("missing integration path parameter %s", source)
		}
		parts := strings.Split(value, "/")
		for i, part := range parts {
			parts[i] = url.PathEscape(part)
		}
		uri = strings.ReplaceAll(uri, "{"+target+"}", strings.Join(parts, "/"))
	}
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(uri, "{}") {
		return nil, errors.New("invalid deployed HTTP proxy URI")
	}
	rawQuery = proxyQuery(rawQuery)
	if rawQuery != "" {
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += rawQuery
	}
	return u, nil
}

// Keep query encoding and duplicate ordinary parameters intact, while removing
// gateway-only presigned authentication/session credentials.
func proxyQuery(raw string) string {
	parts := strings.Split(raw, "&")
	out := parts[:0]
	for _, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		name, err := url.QueryUnescape(name)
		if err == nil {
			switch strings.ToLower(name) {
			case "x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-expires", "x-amz-signedheaders", "x-amz-signature", "x-amz-security-token":
				continue
			}
		}
		out = append(out, part)
	}
	return strings.Join(out, "&")
}

// Remove both standard hop-by-hop fields and every field nominated by any
// Connection header value. Never mutate ingress or the transport's headers.
func proxyHeaders(source http.Header) http.Header {
	out := source.Clone()
	for _, value := range source.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			out.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Host"} {
		out.Del(name)
	}
	return out
}

func (s *Handler) executeHTTPProxy(w http.ResponseWriter, r *http.Request, route *Route, body []byte, metrics *requestMetrics, observation *requestObservation) {
	u, err := httpProxyURL(route.HTTPProxy, route.PathParameters, r.URL.RawQuery)
	if err != nil {
		observation.responseType, observation.integrationError = "API_CONFIGURATION_ERROR", err.Error()
		writeIntegrationFailure(w, true)
		return
	}
	timeout := 29 * time.Second
	if route.IntegrationTimeoutMillis > 0 {
		timeout = time.Duration(route.IntegrationTimeoutMillis) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	method := route.HTTPProxy.Method
	if method == "ANY" {
		method = r.Method
	}
	request, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		observation.responseType, observation.integrationError = "API_CONFIGURATION_ERROR", err.Error()
		writeIntegrationFailure(w, true)
		return
	}
	request.Header = proxyHeaders(r.Header)
	for _, name := range []string{"Content-Length", "Expect", "Content-MD5", "Max-Forwards", "Server", "Via", "X-HTTP-Method-Override"} {
		request.Header.Del(name)
	}
	for _, value := range request.Header.Values("Authorization") {
		if route.AuthorizationType == "AWS_IAM" || strings.HasPrefix(value, "AWS4-HMAC-SHA256 ") || strings.HasPrefix(value, "AWS4-ECDSA-P256-SHA256 ") {
			request.Header.Del("Authorization")
			break
		}
	}
	// Session credentials belong to gateway authentication, never the backend.
	request.Header.Del("X-Amz-Security-Token")
	// Do not implicitly negotiate gzip and let net/http decompress a payload.
	// Explicit client negotiation, and resulting response bytes, pass unchanged.
	if request.Header.Get("Accept-Encoding") == "" {
		request.Header.Set("Accept-Encoding", "identity")
	}
	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}
	started := time.Now()
	metrics.integrated = true
	response, err := s.httpClient.Do(request)
	if err == nil {
		defer response.Body.Close()
		observation.integrationStatus = response.StatusCode
	}
	var payload []byte
	if err == nil {
		if response.StatusCode < 200 || response.StatusCode > 599 {
			err = errors.New("unsupported HTTP proxy response status")
		} else {
			payload, err = io.ReadAll(io.LimitReader(response.Body, (10<<20)+1))
			if len(payload) > 10<<20 {
				err = errors.New("HTTP proxy response exceeds 10 MiB")
			}
		}
	}
	metrics.integrationLatency = time.Since(started)
	if err != nil {
		observation.integrationError = err.Error()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			observation.responseType = "INTEGRATION_TIMEOUT"
			writeRejection(w, &rejection{http.StatusGatewayTimeout, "Endpoint request timed out"})
		} else {
			observation.responseType = "INTEGRATION_FAILURE"
			writeRejection(w, &rejection{http.StatusBadGateway, "Internal server error"})
		}
		return
	}
	metrics.receivedPayload = true
	metrics.processedBytes = metrics.requestBytes + int64(len(payload))
	observation.backendStatus = response.StatusCode
	headers := proxyHeaders(response.Header)
	// API Gateway remaps these backend fields rather than exposing them as
	// gateway authentication challenges or identity headers.
	for _, name := range []string{"Authorization", "Content-MD5", "Date", "Max-Forwards", "Server", "User-Agent", "WWW-Authenticate"} {
		if values, ok := headers[http.CanonicalHeaderKey(name)]; ok {
			headers["X-Amzn-Remapped-"+http.CanonicalHeaderKey(name)] = values
			headers.Del(name)
		}
	}
	headers.Del("Content-Length")
	for name, values := range headers {
		// Gateway request IDs are generated at ingress, not by the backend.
		if strings.EqualFold(name, "x-amzn-RequestId") || strings.EqualFold(name, "x-amz-apigw-id") {
			continue
		}
		w.Header()[name] = values
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	// HEAD carries backend representation length but never a response body.
	if r.Method == "HEAD" {
		if value := response.Header.Get("Content-Length"); value != "" {
			w.Header().Set("Content-Length", value)
		}
	} else if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotModified {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
	}
	w.WriteHeader(response.StatusCode)
	if r.Method != "HEAD" {
		_, _ = w.Write(payload)
	}
}
