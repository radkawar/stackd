package stackd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNetworkingDiagnosticsRequireDirectLoopback(t *testing.T) {
	for _, test := range []struct {
		name, peer, forwarded, xff, method string
		want                               int
	}{
		{name: "IPv4", peer: "127.0.0.1:49152", method: http.MethodGet, want: http.StatusOK},
		{name: "IPv6", peer: "[::1]:49152", method: http.MethodGet, want: http.StatusOK},
		{name: "mapped IPv4", peer: "[::ffff:127.0.0.1]:49152", method: http.MethodGet, want: http.StatusOK},
		{name: "external peer cannot claim loopback", peer: "192.0.2.10:49152", xff: "127.0.0.1", method: http.MethodGet, want: http.StatusForbidden},
		{name: "loopback proxy is not direct", peer: "127.0.0.1:49152", xff: "192.0.2.10", method: http.MethodGet, want: http.StatusForbidden},
		{name: "standard forwarding header", peer: "127.0.0.1:49152", forwarded: "for=192.0.2.10", method: http.MethodGet, want: http.StatusForbidden},
		{name: "missing socket peer", peer: "", method: http.MethodGet, want: http.StatusForbidden},
		{name: "not mutable", peer: "127.0.0.1:49152", method: http.MethodPost, want: http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := &Stack{networking: &NetworkingInfo{}}
			request := httptest.NewRequest(test.method, "/_stackd/network", nil)
			request.RemoteAddr = test.peer
			request.Header.Set("Forwarded", test.forwarded)
			request.Header.Set("X-Forwarded-For", test.xff)
			response := httptest.NewRecorder()
			stack.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestNetworkingDiagnosticsRemainDisabledUnlessConfigured(t *testing.T) {
	stack := &Stack{}
	request := httptest.NewRequest(http.MethodGet, "/_stackd/network", nil)
	request.RemoteAddr = "127.0.0.1:49152"
	response := httptest.NewRecorder()
	stack.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unconfigured diagnostics status = %d, want 404", response.Code)
	}
}
