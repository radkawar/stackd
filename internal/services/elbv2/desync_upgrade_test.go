package elbv2

import (
	"bufio"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestNativeDesyncUpgradeFinishesResponseBeforeClosure(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, ambiguous := range []bool{false, true} {
			name := map[bool]string{false: "HTTP", true: "HTTPS"}[secure] + map[bool]string{false: "/CompliantTunnel", true: "/AmbiguousClosure"}[ambiguous]
			t.Run(name, func(t *testing.T) {
				h := nativeDesyncProxy(t, secure)
				conn := h.dial(t)
				raw := "GET /upgrade HTTP/1.1\r\nHost: alb.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
				if ambiguous {
					raw = "POST /upgrade HTTP/1.1\r\nHost: alb.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\n"
				}
				if _, err := io.WriteString(conn, raw); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(conn)
				response, err := http.ReadResponse(reader, nil)
				if err != nil || response.StatusCode != 101 || response.Header.Get("Upgrade") != "websocket" {
					t.Fatalf("upgrade response was not completed before closure: response=%v err=%v", response, err)
				}
				observed := <-h.observed
				if observed.close != ambiguous {
					t.Fatalf("native upgrade target Close=%v, ambiguity=%v", observed.close, ambiguous)
				}
				if ambiguous {
					// Shorter than either native idle timer: an inactivity fallback is
					// not proof of deliberate closure at the complete 101 boundary.
					_ = conn.SetReadDeadline(time.Now().Add(time.Second))
					assertDesyncClientClosed(t, reader)
				} else {
					if _, err := io.WriteString(conn, "live-tunnel"); err != nil {
						t.Fatal(err)
					}
					var echoed [len("live-tunnel")]byte
					if _, err := io.ReadFull(reader, echoed[:]); err != nil || string(echoed[:]) != "live-tunnel" {
						t.Fatalf("compliant native upgrade no longer streams: %q err=%v", echoed, err)
					}
					_ = conn.Close()
				}
				select {
				case address := <-h.targetClosed:
					if address != observed.remoteAddress {
						t.Fatalf("upgrade closed wrong target: %s != %s", address, observed.remoteAddress)
					}
				case <-time.After(time.Second):
					t.Fatal("upgrade closure did not release its real target socket")
				}
			})
		}
	}
}
