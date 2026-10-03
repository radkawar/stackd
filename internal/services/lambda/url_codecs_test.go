package lambda

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"stackd/iam/policy"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
)

func TestFunctionURLNativeResponses(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/lambda/url_http_codecs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Label                string           `json:"label"`
			InvokeMode           string           `json:"invoke_mode"`
			Method               string           `json:"method"`
			RequestHeaders       [][2]string      `json:"request_headers"`
			Cors                 *FunctionURLCORS `json:"cors"`
			Streamed             bool             `json:"streamed"`
			RuntimeContentType   string           `json:"runtime_content_type"`
			RuntimePayloadBase64 string           `json:"runtime_payload_base64"`
			FunctionError        bool             `json:"function_error"`
			Status               int              `json:"status"`
			Headers              [][2]string      `json:"headers"`
			BodyBase64           string           `json:"body_base64"`
			Preflight            bool             `json:"preflight"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.Cases {
		t.Run(test.Label, func(t *testing.T) {
			r := httptest.NewRequest(test.Method, "http://localhost/", nil)
			for _, header := range test.RequestHeaders {
				r.Header.Add(header[0], header[1])
			}
			w := httptest.NewRecorder()
			preflight := functionURLPreflight(w, r, test.Cors)
			if preflight != test.Preflight {
				t.Fatalf("preflight intercepted=%v, native=%v", preflight, test.Preflight)
			}
			if !preflight {
				payload, err := base64.StdEncoding.DecodeString(test.RuntimePayloadBase64)
				if err != nil {
					t.Fatal(err)
				}
				if test.InvokeMode == "RESPONSE_STREAM" {
					events := make(chan api.InvokeWithResponseStreamResponseEvent, (len(payload)+2)/3)
					// Three-byte fragments split both metadata JSON and its NUL delimiter.
					for rest := payload; len(rest) != 0; {
						n := min(len(rest), 3)
						events <- api.InvokeWithResponseStreamResponseEvent{PayloadChunk: &api.InvokeResponseStreamUpdate{Payload: rest[:n]}}
						rest = rest[n:]
					}
					close(events)
					stream := &invocationStream{events: events, contentType: test.RuntimeContentType, streamed: test.Streamed, bufferedPayload: payload}
					err = writeStreamingFunctionURLResponse(t.Context(), w, r, stream, test.Cors)
				} else {
					out := &invocationOutput{InvokeOutput: api.InvokeOutput{Payload: payload}, streamed: test.Streamed, runtimeContentType: test.RuntimeContentType}
					if test.FunctionError {
						out.FunctionError = new(api.String("Unhandled"))
					}
					err = writeBufferedFunctionURLResponse(w, r, out, test.Cors)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if w.Code != test.Status {
				t.Fatalf("status=%d, native=%d", w.Code, test.Status)
			}
			wantBody, err := base64.StdEncoding.DecodeString(test.BodyBase64)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(w.Body.Bytes(), wantBody) {
				t.Fatalf("body=%q, native=%q", w.Body.Bytes(), wantBody)
			}
			wantHeaders := make(http.Header)
			for _, header := range test.Headers {
				wantHeaders.Add(header[0], header[1])
			}
			gotHeaders := w.Result().Header
			gotHeaders.Del("Content-Length")
			if !reflect.DeepEqual(gotHeaders, wantHeaders) {
				t.Fatalf("headers=%v, native=%v", gotHeaders, wantHeaders)
			}
		})
	}
}

func TestFunctionURLRequestPathCookiesAndTrustedTransport(t *testing.T) {
	r := httptest.NewRequest("GET", "http://localhost/a%2Fb/%E2%98%83/space%20here?dup=one&dup=two%2Cthree&plus=a+b&encoded=a%2Bb&empty=&bare&%65nc=one&enc=two", nil)
	r.Header.Add("Cookie", "a=1; b=two")
	r.Header.Add("Cookie", "c=3")
	r.Header.Set("X-Forwarded-For", "192.0.2.99")
	r.Header.Set("X-Amzn-Tls-Version", "forged")
	r.Header.Set("X-Amzn-Tls-Cipher-Suite", "forged")
	r = r.WithContext(awsctx.WithMetadata(r.Context(), awsctx.Metadata{AccountID: policy.AnonymousAccountID, TransportKnown: true, SourceIP: "192.0.2.10", UserAgent: "actual-client"}))
	decoded, wire := decodeFunctionURLRequest(r, "url-id", time.Unix(100, 0), "")
	if wire != nil {
		t.Fatal(wire)
	}
	var event functionURLEvent
	if err := json.Unmarshal(decoded.Payload, &event); err != nil {
		t.Fatal(err)
	}
	if event.RawPath != "/a%2Fb/%E2%98%83/space%20here" || event.RequestContext.HTTP.Path != "/a/b/☃/space here" {
		t.Fatalf("raw=%q decoded=%q", event.RawPath, event.RequestContext.HTTP.Path)
	}
	wantQuery := map[string]string{"dup": "one,two,three", "plus": "a b", "encoded": "a+b", "empty": "", "bare": "", "enc": "one,two"}
	if !reflect.DeepEqual(event.QueryStringParameters, wantQuery) || !reflect.DeepEqual(event.Cookies, []string{"a=1", "b=two", "c=3"}) {
		t.Fatalf("query=%v cookies=%v", event.QueryStringParameters, event.Cookies)
	}
	if event.RequestContext.HTTP.SourceIP != "192.0.2.10" || event.RequestContext.HTTP.UserAgent != "actual-client" || event.Headers["x-forwarded-for"] != "192.0.2.99" {
		t.Fatalf("untrusted transport projection: %+v", event)
	}
	if _, exists := event.Headers["x-amzn-tls-version"]; exists {
		t.Fatal("fabricated TLS transport")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(decoded.Payload, &fields); err != nil {
		t.Fatal(err)
	}
	var requestContext map[string]json.RawMessage
	if err := json.Unmarshal(fields["requestContext"], &requestContext); err != nil {
		t.Fatal(err)
	}
	if fields["body"] != nil || requestContext["authorizer"] != nil {
		t.Fatal("absent native fields became present")
	}
}

func TestFunctionURLRequestBodyClassification(t *testing.T) {
	for _, test := range []struct {
		name, contentType string
		body              []byte
		encoded           bool
	}{
		{"json", "application/json; charset=utf-8", []byte("{\"hello\":\"snowman ☃\"}"), false},
		{"binary", "application/octet-stream", []byte{0, 255, 65, 10}, true},
		{"no-type", "", []byte("abc"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://localhost/", bytes.NewReader(test.body))
			if test.contentType != "" {
				r.Header.Set("Content-Type", test.contentType)
			}
			out, wire := decodeFunctionURLRequest(r, "url-id", time.Unix(100, 0), "")
			if wire != nil {
				t.Fatal(wire)
			}
			var event functionURLEvent
			if err := json.Unmarshal(out.Payload, &event); err != nil {
				t.Fatal(err)
			}
			body := []byte(event.Body)
			if event.IsBase64Encoded {
				var err error
				body, err = base64.StdEncoding.DecodeString(event.Body)
				if err != nil {
					t.Fatal(err)
				}
			}
			if event.IsBase64Encoded != test.encoded || !bytes.Equal(body, test.body) {
				t.Fatalf("body=%q base64=%v", event.Body, event.IsBase64Encoded)
			}
		})
	}
}

type functionURLChunkWriter struct {
	header  http.Header
	chunks  chan []byte
	headers chan int
}

func (w *functionURLChunkWriter) Header() http.Header    { return w.header }
func (w *functionURLChunkWriter) WriteHeader(status int) { w.headers <- status }
func (w *functionURLChunkWriter) Write(payload []byte) (int, error) {
	w.chunks <- bytes.Clone(payload)
	return len(payload), nil
}
func (w *functionURLChunkWriter) Flush() {}

func TestFunctionURLStreamingFlushesBeforeCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	events := make(chan api.InvokeWithResponseStreamResponseEvent)
	stream := &invocationStream{events: events, streamed: true, contentType: functionURLIntegrationContentType}
	w := &functionURLChunkWriter{header: make(http.Header), headers: make(chan int, 1), chunks: make(chan []byte, 1)}
	r := httptest.NewRequest("GET", "http://localhost/", nil)
	done := make(chan error, 1)
	go func() { done <- writeStreamingFunctionURLResponse(ctx, w, r, stream, nil) }()
	first := append([]byte(`{"statusCode":206,"headers":{"Content-Type":"text/plain"}}`), functionURLMetadataDelimiter...)
	first = append(first, []byte("prefix")...)
	select {
	case events <- api.InvokeWithResponseStreamResponseEvent{PayloadChunk: &api.InvokeResponseStreamUpdate{Payload: first}}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case status := <-w.headers:
		if status != 206 {
			t.Fatalf("status=%d", status)
		}
	case <-ctx.Done():
		t.Fatal("headers withheld until completion")
	}
	select {
	case body := <-w.chunks:
		if string(body) != "prefix" {
			t.Fatalf("first delivered bytes=%q", body)
		}
	case <-ctx.Done():
		t.Fatal("prefix withheld until completion")
	}
	// No completion has been sent yet: receiving the prefix proves incremental delivery.
	select {
	case events <- api.InvokeWithResponseStreamResponseEvent{InvokeComplete: &api.InvokeWithResponseStreamCompleteEvent{ErrorCode: new(api.String("RuntimeError"))}}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	close(events)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if len(w.header.Values("Trailer")) != 0 {
		t.Fatal("invented completion trailers")
	}
}
