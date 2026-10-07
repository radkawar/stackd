package main

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransparentRoutingUsesSameMappedClientScopeAsDNS(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	settings := registerNetworkingFlags(flags)
	if err := flags.Parse([]string{"-transparent-client", "::ffff:192.0.2.0/120"}); err != nil {
		t.Fatal(err)
	}
	handler := settings.transparentHandler(http.NotFoundHandler())
	for _, test := range []struct {
		peer string
		want int
	}{
		{peer: "192.0.2.10:49152", want: http.StatusNotFound},
		{peer: "[::ffff:192.0.2.10]:49152", want: http.StatusNotFound},
		{peer: "192.0.3.10:49152", want: http.StatusForbidden},
	} {
		request := httptest.NewRequest(http.MethodGet, "https://sqs.us-east-1.amazonaws.com/", nil)
		request.RemoteAddr = test.peer
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("peer %s status = %d, want %d", test.peer, response.Code, test.want)
		}
	}
}

func TestTransparentRoutingRejectsMappedGlobalScope(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	registerNetworkingFlags(flags)
	if err := flags.Parse([]string{"-transparent-client", "::ffff:0.0.0.0/96"}); err == nil {
		t.Fatal("mapped global IPv4 prefix accepted for isolated routing")
	}
}
