package apigatewayexec

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awswire"
)

func proxyTestRoute(uri, method string) *Route {
	return &Route{APIID: "api", Stage: "live", ProtocolType: "REST", AuthorizationType: "NONE", IntegrationTimeoutMillis: 1000, HTTPProxy: &HTTPProxyIntegration{URI: uri, Method: method}}
}

func TestRESTHTTPProxyActualProtocolTransport(t *testing.T) {
	input := []byte{0, 255, 'x', '\n'}
	output := []byte{255, 0, 'y', '\n'}
	type received struct {
		method, uri, host string
		header            http.Header
		body              []byte
	}
	requests := make(chan received, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- received{r.Method, r.RequestURI, r.Host, r.Header.Clone(), body}
		w.Header().Add("Set-Cookie", "one=1")
		w.Header().Add("Set-Cookie", "two=2")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Connection", "X-Backend-Hop")
		w.Header().Set("X-Backend-Hop", "secret")
		w.Header().Set("WWW-Authenticate", "Basic realm=backend")
		w.Header().Set("x-amzn-RequestId", "backend-must-not-spoof")
		w.WriteHeader(418)
		_, _ = w.Write(output)
	}))
	defer backend.Close()
	route := proxyTestRoute(backend.URL+"/site/{proxy}?fixed=a%2Bb", "ANY")
	route.PathParameters = map[string]string{"proxy": "a b/%2F/c"}
	route.HTTPProxy.PathParameters = map[string]string{"proxy": "proxy"}
	route.GatewayResponses = map[string]GatewayResponse{"DEFAULT_4XX": {StatusCode: 401, Headers: map[string]string{"X-Gateway": "wrong"}}}
	gateway := httptest.NewServer(New(Config{REST: restTestResolver{route: route}}))
	defer gateway.Close()
	// The frontend must not implicitly add gzip negotiation: this case checks
	// the proxy's default for an ingress request with no Accept-Encoding.
	client := *gateway.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DisableCompression = true
	defer transport.CloseIdleConnections()
	client.Transport = transport
	request, _ := http.NewRequest("PATCH", gateway.URL+Prefix+"api/live/ignored?dup=one&dup=two&plus=%2B&X-Amz-Security-Token=session&X-Amz-Signature=signed", bytes.NewReader(input))
	request.Header["X-Multi"] = []string{"one", "two"}
	request.Header["Connection"] = []string{"X-Client-Hop", "X-Other-Hop"}
	request.Header.Set("X-Client-Hop", "private")
	request.Header.Set("X-Other-Hop", "private")
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=secret")
	request.Header.Set("X-Amz-Security-Token", "session")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Host = "signed.gateway.example"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 418 || !bytes.Equal(body, output) || response.Header.Get("X-Gateway") != "" || response.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("proxy response = %d %v %q", response.StatusCode, response.Header, body)
	}
	if len(response.Header.Values("Set-Cookie")) != 2 || response.Header.Get("X-Backend-Hop") != "" || response.Header.Get("WWW-Authenticate") != "" || response.Header.Get("X-Amzn-Remapped-WWW-Authenticate") != "Basic realm=backend" || response.Header.Get("x-amzn-RequestId") == "backend-must-not-spoof" {
		t.Fatalf("response headers lost boundary: %v", response.Header)
	}
	got := <-requests
	if got.method != "PATCH" || got.uri != "/site/a%20b/%252F/c?fixed=a%2Bb&dup=one&dup=two&plus=%2B" || got.host != strings.TrimPrefix(backend.URL, "http://") || !bytes.Equal(got.body, input) {
		t.Fatalf("actual backend request = %+v", got)
	}
	if len(got.header.Values("X-Multi")) != 2 || got.header.Get("X-Client-Hop") != "" || got.header.Get("X-Other-Hop") != "" || got.header.Get("Authorization") != "" || got.header.Get("X-Amz-Security-Token") != "" || got.header.Get("Accept-Encoding") != "identity" {
		t.Fatalf("backend header boundary = %v", got.header)
	}
}

type proxyTestWAF struct{ blocked bool }

func (w proxyTestWAF) InspectStage(context.Context, WebACLRequest) (WebACLVerdict, error) {
	return WebACLVerdict{Blocked: w.blocked, InsertHeaders: http.Header{"X-Amzn-Waf-Trace": {"inspected"}}}, nil
}

func TestRESTHTTPProxyCannotBypassAdmission(t *testing.T) {
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Amzn-Waf-Trace") != "inspected" {
			t.Error("WAF insertion missing")
		}
		_, _ = w.Write([]byte("admitted"))
	}))
	defer backend.Close()
	for _, test := range []struct {
		name, auth string
		blocked    bool
		want       int
	}{
		{"waf", "NONE", true, 403}, {"iam", "AWS_IAM", false, 500}, {"admitted", "NONE", false, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			route := proxyTestRoute(backend.URL, "GET")
			route.AuthorizationType = test.auth
			before := calls.Load()
			w := httptest.NewRecorder()
			New(Config{REST: restTestResolver{route: route}, WebACLs: proxyTestWAF{test.blocked}}).ServeHTTP(w, httptest.NewRequest("GET", Prefix+"api/live/", nil))
			if w.Code != test.want {
				t.Fatalf("status = %d, want %d", w.Code, test.want)
			}
			wantCalls := int32(0)
			if test.want == 200 {
				wantCalls = 1
			}
			if calls.Load()-before != wantCalls {
				t.Fatal("integration ran before authorization/WAF admission")
			}
		})
	}
}

func TestRESTHTTPProxyRedirectAndCompressionAreTransported(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	var encoded bytes.Buffer
	zw := gzip.NewWriter(&encoded)
	_, _ = zw.Write([]byte("compressed backend bytes"))
	_ = zw.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", target.URL)
			w.WriteHeader(307)
			_, _ = w.Write([]byte("do not follow"))
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(encoded.Bytes())
	}))
	defer backend.Close()
	injected := *backend.Client()
	injected.CheckRedirect = func(*http.Request, []*http.Request) error {
		t.Error("injected redirect policy must not run")
		return nil
	}
	for _, path := range []string{"/redirect", "/compressed"} {
		w := httptest.NewRecorder()
		New(Config{REST: restTestResolver{route: proxyTestRoute(backend.URL+path, "GET")}, HTTPClient: &injected}).ServeHTTP(w, httptest.NewRequest("GET", Prefix+"api/live/", nil))
		if path == "/redirect" {
			if w.Code != 307 || w.Header().Get("Location") != target.URL || w.Body.String() != "do not follow" || redirected.Load() != 0 {
				t.Fatal("proxy followed redirect")
			}
		} else if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(w.Body.Bytes(), encoded.Bytes()) {
			t.Fatal("transport implicitly decompressed backend payload")
		}
	}
}

func TestRESTHTTPProxyTimeoutCancellationAndResponseLimit(t *testing.T) {
	cancelled := make(chan struct{}, 2)
	entered := make(chan struct{}, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, (10<<20)+1))
			return
		}
		if r.URL.Path == "/cancel" {
			entered <- struct{}{}
		}
		<-r.Context().Done()
		cancelled <- struct{}{}
	}))
	defer backend.Close()
	for _, test := range []struct {
		path    string
		timeout int32
		want    int
	}{{"/slow", 50, 504}, {"/large", 1000, 502}} {
		route := proxyTestRoute(backend.URL+test.path, "GET")
		route.IntegrationTimeoutMillis = test.timeout
		w := httptest.NewRecorder()
		New(Config{REST: restTestResolver{route: route}}).ServeHTTP(w, httptest.NewRequest("GET", Prefix+"api/live/", nil))
		if w.Code != test.want {
			t.Fatalf("%s status=%d, want %d", test.path, w.Code, test.want)
		}
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("deadline did not cancel backend")
	}
	ctx, cancel := context.WithCancel(t.Context())
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		New(Config{REST: restTestResolver{route: proxyTestRoute(backend.URL+"/cancel", "GET")}}).ServeHTTP(w, httptest.NewRequest("GET", Prefix+"api/live/", nil).WithContext(ctx))
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("cancel test did not reach backend")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("request cancellation did not terminate integration")
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("request cancellation did not close backend request")
	}
	if w.Code != 502 {
		t.Fatalf("cancellation status=%d", w.Code)
	}
}

func TestRESTHTTPProxyBackendHEADAndDefaultContentType(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("default request content type missing")
		}
		if r.Header.Get("Authorization") != "Bearer backend-token" {
			t.Error("non-AWS authorization lost")
		}
		w.Header().Set("Content-Length", "123")
		w.Header()["Content-Type"] = nil
		w.WriteHeader(200)
	}))
	defer backend.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("HEAD", Prefix+"api/live/", nil)
	r.Header.Set("Authorization", "Bearer backend-token")
	New(Config{REST: restTestResolver{route: proxyTestRoute(backend.URL, "HEAD")}}).ServeHTTP(w, r)
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "123" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("HEAD response=%d %v %q", w.Code, w.Header(), w.Body.String())
	}
}

type proxyTestAuthentication struct{}

func (proxyTestAuthentication) Authenticate(r *http.Request, service, region string) (*http.Request, *awswire.Error) {
	return r, nil
}

type proxyTestInvocationPolicy struct {
	deny     bool
	requests chan authorization.Request
}

func (p proxyTestInvocationPolicy) Authorize(_ context.Context, request authorization.Request) *awswire.Error {
	p.requests <- request
	if p.deny {
		return &awswire.Error{Code: "AccessDenied", StatusCode: 403, Message: "explicit deny"}
	}
	return nil
}

func TestRESTHTTPProxyUsesScopedInvocationPolicyBeforeEgress(t *testing.T) {
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Amz-Security-Token") != "" {
			t.Error("IAM credentials escaped to HTTP backend")
		}
		_, _ = w.Write([]byte("policy admitted"))
	}))
	defer backend.Close()
	for _, deny := range []bool{true, false} {
		route := proxyTestRoute(backend.URL, "GET")
		route.AuthorizationType = "AWS_IAM"
		route.Partition, route.AccountID, route.Region = "aws", "123456789012", "us-east-1"
		requests := make(chan authorization.Request, 1)
		before := calls.Load()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", Prefix+"api/live/resource", nil)
		r.Header.Set("Authorization", "Bearer gateway-only")
		r.Header.Set("X-Amz-Security-Token", "gateway-session")
		New(Config{REST: restTestResolver{route: route}, Authentication: proxyTestAuthentication{}, Authorization: proxyTestInvocationPolicy{deny, requests}}).ServeHTTP(w, r)
		request := <-requests
		if request.Action != "execute-api:Invoke" || request.ResourceARN != "arn:aws:execute-api:us-east-1:123456789012:api/live/GET/resource" || request.ResourceAccountID != "123456789012" {
			t.Fatalf("unscoped policy request=%+v", request)
		}
		if deny {
			if w.Code != 403 || calls.Load() != before {
				t.Fatal("explicit invocation deny failed before egress")
			}
		} else if w.Code != 200 || calls.Load() != before+1 {
			t.Fatal("admitted scoped invocation did not reach actual backend")
		}
	}
}
