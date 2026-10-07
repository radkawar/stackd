package apigatewayexec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"stackd/internal/awswire"
	"strings"
	"testing"
	"time"
)

func TestRESTBinaryFirstAcceptNegotiation(t *testing.T) {
	for _, tc := range []struct {
		accept string
		types  []string
		binary bool
	}{
		{"image/webp,image/png;q=0.9", []string{"image/png"}, false},
		{"image/webp,image/png;q=0.9", []string{"image/*"}, true},
		{"application/json,image/png", []string{"image/png"}, false},
		{"image/png", nil, false},
		{"image/png; charset=utf-8", []string{"image/png"}, true},
	} {
		t.Run(tc.accept+strings.Join(tc.types, ","), func(t *testing.T) {
			matched := binaryMedia(tc.accept, tc.types)
			if matched != tc.binary {
				t.Fatalf("match = %v, want %v", matched, tc.binary)
			}
			out := httptest.NewRecorder()
			if !writeProxyResponse(out, []byte(`{"statusCode":200,"body":"AP8=","isBase64Encoded":true}`), false, matched) {
				t.Fatal("valid response rejected")
			}
			want := "AP8="
			if tc.binary {
				want = string([]byte{0, 255})
			}
			if out.Body.String() != want {
				t.Fatalf("body = %q, want %q", out.Body.String(), want)
			}
		})
	}
}

func TestRESTGatewayResponseOnlyGatewayErrors(t *testing.T) {
	route := &Route{GatewayResponses: map[string]GatewayResponse{
		"DEFAULT_4XX": {StatusCode: 418, Headers: map[string]string{"Access-Control-Allow-Origin": "*"}, Templates: map[string]string{"application/json": `{"reason":$context.error.messageString}`}},
		"DEFAULT_5XX": {StatusCode: 503, Headers: map[string]string{"X-Gateway": "failure"}},
	}}
	for _, status := range []int{403, 502} {
		out := httptest.NewRecorder()
		w := &gatewayResponseWriter{ResponseWriter: out, route: route, request: httptest.NewRequest("GET", "/missing", nil)}
		writeRejection(w, &rejection{status, `denied "token"`})
		if status == 403 {
			if out.Code != 418 || out.Header().Get("Access-Control-Allow-Origin") != "*" || out.Body.String() != `{"reason":"denied \"token\""}` {
				t.Fatalf("custom 4xx = %d %s", out.Code, out.Body.String())
			}
		} else if out.Code != 503 || out.Header().Get("X-Gateway") != "failure" {
			t.Fatalf("custom 5xx = %d", out.Code)
		}
	}
	out := httptest.NewRecorder()
	w := &gatewayResponseWriter{ResponseWriter: out, route: route, request: httptest.NewRequest("GET", "/", nil)}
	if !writeProxyResponse(w, []byte(`{"statusCode":403,"body":"backend denied"}`), false, false) {
		t.Fatal("backend response rejected")
	}
	if out.Code != http.StatusForbidden || out.Header().Get("Access-Control-Allow-Origin") != "" || out.Body.String() != "backend denied" {
		t.Fatal("gateway response rewrote backend response")
	}
}

func TestRESTMalformedProxyUsesGatewayResponse(t *testing.T) {
	out := httptest.NewRecorder()
	w := &gatewayResponseWriter{ResponseWriter: out, request: httptest.NewRequest("GET", "/", nil), route: &Route{GatewayResponses: map[string]GatewayResponse{"DEFAULT_5XX": {StatusCode: 503}}}}
	if writeProxyResponse(w, []byte(`{"statusCode":200,"body":"!","isBase64Encoded":true}`), false, true) {
		t.Fatal("invalid base64 accepted")
	}
	if out.Code != 503 {
		t.Fatalf("status = %d", out.Code)
	}
}

type restTestResolver struct {
	Resolver
	route *Route
	err   error
}

func (r restTestResolver) Resolve(context.Context, string, string, string, string) (*Route, error) {
	return r.route, r.err
}

func TestRESTMockRunsAfterAuthorization(t *testing.T) {
	for _, auth := range []string{"NONE", "AWS_IAM"} {
		route := &Route{APIID: "api", Stage: "test", ProtocolType: "REST", AuthorizationType: auth, Mock: &MockIntegration{StatusCode: 200, Headers: map[string]string{"Access-Control-Allow-Origin": "*"}}}
		out := httptest.NewRecorder()
		New(Config{REST: restTestResolver{route: route}}).ServeHTTP(out, httptest.NewRequest("OPTIONS", Prefix+"api/test/path", nil))
		if auth == "NONE" {
			if out.Code != 200 || out.Header().Get("Access-Control-Allow-Origin") != "*" {
				t.Fatal("MOCK CORS not executed")
			}
		} else if out.Code != 500 || out.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("MOCK bypassed IAM authorization")
		}
	}
}

func TestRESTUnknownRouteUsesLiveGatewayConfiguration(t *testing.T) {
	route := &Route{APIID: "api", ProtocolType: "REST", GatewayResponses: map[string]GatewayResponse{"DEFAULT_4XX": {StatusCode: 404, Headers: map[string]string{"X-Live": "yes"}}}}
	out := httptest.NewRecorder()
	New(Config{REST: restTestResolver{route: route, err: &awswire.Error{StatusCode: 403, Message: "Missing Authentication Token"}}}).ServeHTTP(out, httptest.NewRequest("GET", Prefix+"api/test/missing", nil))
	if out.Code != 404 || out.Header().Get("X-Live") != "yes" {
		t.Fatal("owned API error lost live gateway config")
	}
}

func TestRESTBinaryRequestUsesConfiguredContentType(t *testing.T) {
	for _, configured := range [][]string{nil, {"application/octet-stream"}} {
		request := httptest.NewRequest("POST", "/test/upload", nil)
		request.Header.Set("Content-Type", "application/octet-stream; charset=binary")
		request = request.WithContext(context.WithValue(request.Context(), requestObservationKey{}, newRequestObservation(request, time.Unix(0, 0), true)))
		route := &Route{Stage: "test", PayloadVersion: "1.0", BinaryMediaTypes: configured}
		payload := (&Handler{}).payload(request, route, "/test/upload", []byte{0, 255}, requestIdentity{}, true).(payloadV1)
		if payload.IsBase64Encoded != (len(configured) != 0) {
			t.Fatal("binary request ignored API media types")
		}
		if len(configured) != 0 && (payload.Body == nil || *payload.Body != "AP8=") {
			t.Fatal("binary request was not encoded")
		}
		if _, err := json.Marshal(payload); err != nil {
			t.Fatal(err)
		}
	}
}
