package lambda

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"stackd/iam/policy"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type functionURLRequest struct {
	Payload []byte
	TraceID string
}

type functionURLEvent struct {
	Version               string                    `json:"version"`
	RouteKey              string                    `json:"routeKey"`
	RawPath               string                    `json:"rawPath"`
	RawQueryString        string                    `json:"rawQueryString"`
	Cookies               []string                  `json:"cookies,omitempty"`
	Headers               map[string]string         `json:"headers"`
	QueryStringParameters map[string]string         `json:"queryStringParameters,omitempty"`
	RequestContext        functionURLRequestContext `json:"requestContext"`
	Body                  string                    `json:"body,omitempty"`
	IsBase64Encoded       bool                      `json:"isBase64Encoded"`
}

type functionURLRequestContext struct {
	AccountID    string                 `json:"accountId"`
	APIID        string                 `json:"apiId"`
	DomainName   string                 `json:"domainName"`
	DomainPrefix string                 `json:"domainPrefix"`
	HTTP         functionURLRequestHTTP `json:"http"`
	RequestID    string                 `json:"requestId"`
	RouteKey     string                 `json:"routeKey"`
	Stage        string                 `json:"stage"`
	Time         string                 `json:"time"`
	TimeEpoch    int64                  `json:"timeEpoch"`
	Authorizer   *functionURLAuthorizer `json:"authorizer,omitempty"`
}

type functionURLRequestHTTP struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Protocol  string `json:"protocol"`
	SourceIP  string `json:"sourceIp"`
	UserAgent string `json:"userAgent,omitempty"`
}

type functionURLAuthorizer struct {
	IAM functionURLIAM `json:"iam"`
}

type functionURLIAM struct {
	AccessKey       string `json:"accessKey"`
	AccountID       string `json:"accountId"`
	CallerID        string `json:"callerId"`
	CognitoIdentity any    `json:"cognitoIdentity"`
	PrincipalOrgID  string `json:"principalOrgId,omitempty"`
	UserARN         string `json:"userArn"`
	UserID          string `json:"userId"`
}

// The gateway authenticates the original target, then removes the private URL
// routing prefix before calling this codec. Proxy headers remain event data;
// they never supply the authenticated identity or transport context.
func decodeFunctionURLRequest(r *http.Request, urlID string, now time.Time, principalOrgID string) (functionURLRequest, *awswire.Error) {
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			var limit *http.MaxBytesError
			if errors.As(err, &limit) {
				return functionURLRequest{}, &awswire.Error{Code: "RequestEntityTooLargeException", Message: "Request body exceeds the function URL limit.", StatusCode: http.StatusRequestEntityTooLarge}
			}
			return functionURLRequest{}, &awswire.Error{Code: "InvalidRequestContentException", Message: "Unable to read request body.", StatusCode: http.StatusBadRequest}
		}
	}
	meta := awsctx.FromContext(r.Context())
	sourceIP := meta.SourceIP
	userAgent := meta.UserAgent
	headers := make(map[string]string, len(r.Header)+8)
	// TODO: Comeback: native mixed-case header multiplicity cannot be recovered
	// after net/http canonicalization; see testdata/aws/lambda/urls_http_headers.json.
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if lower == "authorization" && meta.AccessKeyID != "" {
			// AWS_IAM consumes SigV4 authorization instead of forwarding it to
			// customer code. NONE leaves application authentication untouched.
			continue
		}
		switch lower {
		case "connection", "transfer-encoding", "keep-alive", "proxy-connection", "upgrade", "te", "trailer":
			continue
		}
		headers[lower] = strings.Join(values, ",")
	}
	headers["host"] = r.Host
	// HEAD and OPTIONS without a body do not gain a synthetic content length.
	if _, exists := headers["content-length"]; !exists && (len(body) != 0 || (r.Method != http.MethodHead && r.Method != http.MethodOptions)) {
		headers["content-length"] = strconv.Itoa(len(body))
	}
	proto, port := "http", "80"
	if r.TLS != nil {
		proto, port = "https", "443"
	}
	if _, explicitPort, err := net.SplitHostPort(r.Host); err == nil {
		port = explicitPort
	}
	if _, exists := headers["x-forwarded-proto"]; !exists {
		headers["x-forwarded-proto"] = proto
	}
	if _, exists := headers["x-forwarded-port"]; !exists {
		headers["x-forwarded-port"] = port
	}
	if _, exists := headers["x-forwarded-for"]; !exists {
		headers["x-forwarded-for"] = sourceIP
	}
	// These describe the actual TLS connection, not similarly named client fields.
	delete(headers, "x-amzn-tls-version")
	delete(headers, "x-amzn-tls-cipher-suite")
	if r.TLS != nil {
		headers["x-amzn-tls-version"] = strings.Replace(tls.VersionName(r.TLS.Version), "TLS ", "TLSv", 1)
		headers["x-amzn-tls-cipher-suite"] = tls.CipherSuiteName(r.TLS.CipherSuite)
	}
	var traceBytes [20]byte
	_, _ = rand.Read(traceBytes[:])
	root := fmt.Sprintf("1-%08x-%s", now.Unix(), hex.EncodeToString(traceBytes[:12]))
	trace := "Root=" + root + ";Parent=" + hex.EncodeToString(traceBytes[12:]) + ";Sampled=0"
	headers["x-amzn-trace-id"] = trace
	rawPath, path := r.URL.EscapedPath(), r.URL.Path
	if rawPath == "" {
		rawPath = "/"
	}
	if path == "" {
		path = "/"
	}
	event := functionURLEvent{Version: "2.0", RouteKey: "$default", RawPath: rawPath, RawQueryString: r.URL.RawQuery, Headers: headers,
		RequestContext: functionURLRequestContext{AccountID: meta.AccountID, APIID: urlID, DomainName: r.Host, DomainPrefix: urlID,
			HTTP:      functionURLRequestHTTP{Method: r.Method, Path: path, Protocol: r.Proto, SourceIP: sourceIP, UserAgent: userAgent},
			RequestID: meta.RequestID, RouteKey: "$default", Stage: "$default", Time: now.UTC().Format("02/Jan/2006:15:04:05 -0700"), TimeEpoch: now.UnixMilli()}}
	if meta.AccountID != policy.AnonymousAccountID && meta.AccessKeyID != "" {
		event.RequestContext.Authorizer = &functionURLAuthorizer{IAM: functionURLIAM{AccessKey: meta.AccessKeyID, AccountID: meta.AccountID, CallerID: meta.PrincipalID, PrincipalOrgID: principalOrgID, UserARN: meta.PrincipalARN, UserID: meta.PrincipalID}}
	}
	for _, line := range r.Header.Values("Cookie") {
		for _, cookie := range strings.Split(line, ";") {
			if cookie = strings.TrimSpace(cookie); cookie != "" {
				event.Cookies = append(event.Cookies, cookie)
			}
		}
	}
	// Decode each pair separately: duplicate decoded names join in wire order.
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		decodedKey, errKey := url.QueryUnescape(key)
		decodedValue, errValue := url.QueryUnescape(value)
		if errKey != nil || errValue != nil {
			continue
		}
		if event.QueryStringParameters == nil {
			event.QueryStringParameters = make(map[string]string)
		}
		if previous, exists := event.QueryStringParameters[decodedKey]; exists {
			decodedValue = previous + "," + decodedValue
		}
		event.QueryStringParameters[decodedKey] = decodedValue
	}
	if len(body) != 0 {
		event.IsBase64Encoded = !functionURLTextContentType(r.Header.Get("Content-Type"))
		if event.IsBase64Encoded {
			event.Body = base64.StdEncoding.EncodeToString(body)
		} else {
			event.Body = string(body)
		}
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return functionURLRequest{}, &awswire.Error{Code: "ServiceException", Message: err.Error(), StatusCode: http.StatusInternalServerError}
	}
	return functionURLRequest{Payload: payload, TraceID: trace}, nil
}

func functionURLTextContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mediaType, "text/") || mediaType == "application/json" || mediaType == "application/xml" || mediaType == "application/javascript" || mediaType == "application/x-www-form-urlencoded" || strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml")
}
