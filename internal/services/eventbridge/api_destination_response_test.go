package eventbridge

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func encodeDestinationResponse(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	if encoding == "" {
		return body
	}
	var buffer bytes.Buffer
	var compressor io.WriteCloser
	switch encoding {
	case "gzip":
		compressor = gzip.NewWriter(&buffer)
	case "raw-deflate":
		var err error
		compressor, err = flate.NewWriter(&buffer, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
	case "deflate":
		compressor = zlib.NewWriter(&buffer)
	default:
		t.Fatalf("unsupported fixture encoding %q", encoding)
	}
	if _, err := compressor.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func destinationResponse(encoding string, body []byte) *http.Response {
	if encoding == "raw-deflate" {
		encoding = "deflate"
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": []string{encoding}}, Body: io.NopCloser(bytes.NewReader(body))}
}

func TestAPIDestinationDecodedResponse(t *testing.T) {
	body := []byte(`[{"marker":"derived","value":49},{"marker":"other","value":52}]`)
	for _, encoding := range []string{"", "gzip", "deflate", "raw-deflate"} {
		t.Run(encoding, func(t *testing.T) {
			var output bytes.Buffer
			rejected := readAPIDestinationResponse(destinationResponse(encoding, encodeDestinationResponse(t, encoding, body)), &output)
			if rejected != nil || !bytes.Equal(output.Bytes(), body) {
				t.Fatalf("decoded response = %q, %v; want %q", output.Bytes(), rejected, body)
			}
		})
	}
}

func TestAPIDestinationResponseWireLimit(t *testing.T) {
	const limit = 6 << 20
	body := []byte(`{"pad":"` + strings.Repeat("x", limit-len(`{"pad":""}`)) + `"}`)
	if rejected := readAPIDestinationResponse(destinationResponse("", body), io.Discard); rejected != nil {
		t.Fatalf("exact wire boundary rejected: %v", rejected)
	}
	body = append(body, ' ')
	rejected := readAPIDestinationResponse(destinationResponse("", body), io.Discard)
	if rejected == nil || rejected.Code != "PayloadTooLargeException" {
		t.Fatalf("oversized wire response = %v; want PayloadTooLargeException", rejected)
	}
	// Native gzip captures deliver >6 MiB decoded after target transformation.
	for _, encoding := range []string{"gzip", "deflate", "raw-deflate"} {
		t.Run(encoding, func(t *testing.T) {
			var output bytes.Buffer
			rejected := readAPIDestinationResponse(destinationResponse(encoding, encodeDestinationResponse(t, encoding, body)), &output)
			if rejected != nil || !bytes.Equal(output.Bytes(), body) {
				t.Fatalf("compressed expanded response: bytes=%d error=%v", output.Len(), rejected)
			}
		})
	}
}

func TestAPIDestinationResponseExpansionSafety(t *testing.T) {
	// Generate the expansion incrementally rather than allocating a bomb fixture.
	var compressed bytes.Buffer
	compressor := gzip.NewWriter(&compressed)
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	for range 65 {
		if _, err := compressor.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	rejected := readAPIDestinationResponse(destinationResponse("gzip", compressed.Bytes()), io.Discard)
	if rejected == nil || rejected.Code != "NotImplementedException" {
		t.Fatalf("unbounded expansion admitted: %v", rejected)
	}
}

func TestAPIDestinationRejectsDamagedCompression(t *testing.T) {
	body := []byte(`{"marker":"must-not-be-delivered"}`)
	for _, encoding := range []string{"gzip", "deflate"} {
		encoded := encodeDestinationResponse(t, encoding, body)
		corrupt := bytes.Clone(encoded)
		corrupt[len(corrupt)-1] ^= 1
		for name, wire := range map[string][]byte{"truncated": encoded[:len(encoded)-2], "checksum": corrupt, "header": []byte("not a compressed stream")} {
			t.Run(encoding+"/"+name, func(t *testing.T) {
				var output bytes.Buffer
				rejected := readAPIDestinationResponse(destinationResponse(encoding, wire), &output)
				// A decoder may produce valid JSON before detecting a bad trailer;
				// callers must receive a failure and discard all those bytes.
				if rejected == nil || rejected.Code != "ServiceUnavailable" {
					t.Fatalf("damaged response admitted: output=%q error=%v", output.Bytes(), rejected)
				}
			})
		}
	}
}

func TestAPIDestinationBodylessEncoding(t *testing.T) {
	for _, row := range []struct {
		method string
		status int
	}{{http.MethodHead, http.StatusOK}, {http.MethodPost, http.StatusNoContent}} {
		t.Run(row.method, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				w.WriteHeader(row.status)
			}))
			defer server.Close()
			request, err := http.NewRequestWithContext(t.Context(), row.method, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Accept-Encoding", "gzip,deflate")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			rejected := readAPIDestinationResponse(response, &output)
			if rejected != nil || output.Len() != 0 {
				t.Fatalf("bodyless response must filter the target: body=%q error=%v", output.Bytes(), rejected)
			}
		})
	}
}
