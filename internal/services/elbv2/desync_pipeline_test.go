package elbv2

import (
	"bufio"
	"io"
	"testing"
	"time"
)

func TestNativeDesyncMixedPipelineVerdictIsolation(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, severe := range []bool{false, true} {
			name := map[bool]string{false: "HTTP", true: "HTTPS"}[secure] + map[bool]string{false: "/CompliantThenAmbiguous", true: "/CompliantThenSevere"}[severe]
			t.Run(name, func(t *testing.T) {
				h := nativeDesyncProxy(t, secure)
				conn := h.dial(t)
				first := "POST /first HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 0\r\n\r\n"
				second := "POST /ambiguous HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\n"
				if severe {
					second = "POST /severe HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nX"
				}
				if _, err := io.WriteString(conn, first+second+"GET /must-not-forward HTTP/1.1\r\nHost: alb.invalid\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(conn)
				// net/http's backgroundRead may observe pipeline input while this
				// first handler runs. Neither the second tier nor its raw 400 may
				// affect or interleave the first compliant response.
				readDesyncResponse(t, reader, 200, "target:/first::", false)
				firstTarget := <-h.observed
				if firstTarget.close || firstTarget.path != "/first" {
					t.Fatalf("later native tier contaminated first target request: %+v", firstTarget)
				}
				wantRequests := uint32(1)
				if severe {
					readDesyncResponse(t, reader, 400, "Bad Request", true)
				} else {
					wantRequests = 2
					readDesyncResponse(t, reader, 200, "target:/ambiguous:data:", true)
					secondTarget := <-h.observed
					if !secondTarget.close || secondTarget.path != "/ambiguous" {
						t.Fatalf("second native tier did not close its own target: %+v", secondTarget)
					}
					select {
					case address := <-h.targetClosed:
						if address != secondTarget.remoteAddress {
							t.Fatalf("closed %s rather than ambiguous socket %s", address, secondTarget.remoteAddress)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("mixed pipeline retained ambiguous target socket")
					}
				}
				assertDesyncClientClosed(t, reader)
				if h.requests.Load() != wantRequests || h.completed.Load() != wantRequests {
					t.Fatalf("mixed pipeline forwarded/completed %d/%d requests, want %d", h.requests.Load(), h.completed.Load(), wantRequests)
				}
			})
		}
	}
}
