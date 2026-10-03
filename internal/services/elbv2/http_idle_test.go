package elbv2

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	api "stackd/internal/awsapi/elbv2"
	"strings"
	"testing"
	"time"
)

func TestHTTPIdleTimeoutOutcomes(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[secure], func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/header":
					<-r.Context().Done()
				case "/body":
					_, _ = io.WriteString(w, "start")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				case "/upload":
					body, err := io.ReadAll(r.Body)
					if err == nil {
						_, _ = w.Write(body)
					}
				case "/stream":
					for range 6 {
						_, _ = io.WriteString(w, "tick")
						w.(http.Flusher).Flush()
						time.Sleep(75 * time.Millisecond)
					}
					_, _ = io.WriteString(w, "done")
				}
			}))
			defer backend.Close()
			policy := newConnectionIdlePolicy(250 * time.Millisecond)
			defer policy.close()
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				c, e := (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
				if e != nil {
					return nil, e
				}
				return policy.wrap(c), nil
			}, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			service := New(Config{Networks: controlNetwork{}})
			defer service.Close()
			scope := Scope{"aws", "000000000000", "us-east-1"}
			lbARN := arn(scope, "loadbalancer/app/idle/1")
			groupARN := arn(scope, "targetgroup/idle/2")
			listenerARN := arn(scope, "listener/app/idle/1/3")
			if err := service.repository.Update(t.Context(), func(tx Transaction) error {
				if e := tx.PutLoadBalancer(LoadBalancerRecord{Scope: scope, Data: api.LoadBalancer{LoadBalancerArn: new(api.LoadBalancerArn(lbARN)), AvailabilityZones: api.AvailabilityZones{{ZoneName: new(api.ZoneName("us-east-1a")), SubnetId: new(api.SubnetId("subnet-a"))}}}}); e != nil {
					return e
				}
				if e := tx.PutTargetGroup(TargetGroupRecord{Scope: scope, Data: api.TargetGroup{TargetGroupArn: new(api.TargetGroupArn(groupARN)), VpcId: new(api.VpcId("vpc-0aeae393af73839cf")), TargetType: new(api.TargetTypeEnum("ip")), Protocol: new(api.ProtocolEnum("HTTP")), LoadBalancerArns: api.LoadBalancerArns{api.LoadBalancerArn(lbARN)}}}); e != nil {
					return e
				}
				if e := tx.PutTarget(TargetRecord{Scope: scope, TargetGroupARN: groupARN, Data: api.TargetDescription{Id: new(api.TargetId("10.0.0.8")), Port: new(api.Port(8080))}, State: "healthy", Version: 1}); e != nil {
					return e
				}
				return tx.PutListener(ListenerRecord{Scope: scope, Data: api.Listener{ListenerArn: new(api.ListenerArn(listenerARN)), LoadBalancerArn: new(api.LoadBalancerArn(lbARN)), Protocol: new(api.ProtocolEnum("HTTP")), Port: new(api.Port(80)), DefaultActions: api.Actions{{Type: new(api.ActionTypeEnum("forward")), TargetGroupArn: new(api.TargetGroupArn(groupARN))}}}})
			}); err != nil {
				t.Fatal(err)
			}
			nativeListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener := idleListener{Listener: nativeListener, policy: policy}
			scheme := "http"
			if secure {
				donor := httptest.NewTLSServer(http.NotFoundHandler())
				listener.tlsConfig = listenerTLSConfig(donor.TLS.Certificates[0])
				donor.Close()
				scheme = "https"
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				service.runtime.serve(w, r, scope, listenerARN, &runtimeNode{transport: transport})
			}), ConnContext: idleHTTPContext, ConnState: idleHTTPState}
			go server.Serve(listener)
			defer server.Close()
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}, Timeout: 2 * time.Second}
			defer client.CloseIdleConnections()
			origin := scheme + "://" + nativeListener.Addr().String()
			if secure {
				partial, err := net.Dial("tcp", nativeListener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				_ = partial.SetDeadline(time.Now().Add(2 * time.Second))
				_, err = partial.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01})
				if err != nil {
					partial.Close()
					t.Fatal(err)
				}
				var response [1]byte
				_, err = partial.Read(response[:])
				_ = partial.Close()
				if timeout, ok := err.(net.Error); err == nil || ok && timeout.Timeout() {
					t.Fatalf("incomplete TLS handshake outlived its idle deadline: %v", err)
				}
			}
			response, err := client.Get(origin + "/header")
			if err != nil {
				t.Fatal("target timeout must be an HTTP response", err)
			}
			if response.StatusCode != 504 {
				t.Fatalf("connected target timeout=%d", response.StatusCode)
			}
			response.Body.Close()
			raw := func(input string) int {
				t.Helper()
				var conn net.Conn
				var e error
				if secure {
					conn, e = tls.Dial("tcp", nativeListener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
				} else {
					conn, e = net.Dial("tcp", nativeListener.Addr().String())
				}
				if e != nil {
					t.Fatal(e)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, e = io.WriteString(conn, input); e != nil {
					t.Fatal(e)
				}
				out, e := http.ReadResponse(bufio.NewReader(conn), nil)
				if e != nil {
					t.Fatal("client timeout must have one HTTP response", e)
				}
				defer out.Body.Close()
				return out.StatusCode
			}
			if got := raw("GET / HTTP/1.1\r\nHost: idle\r\n"); got != 408 {
				t.Fatalf("incomplete header=%d", got)
			}
			if got := raw("POST /upload HTTP/1.1\r\nHost: idle\r\nContent-Length: 5\r\n\r\n"); got != 408 {
				t.Fatalf("incomplete upload=%d", got)
			}
			response, err = client.Get(origin + "/body")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 200 || string(body) != "start" || err == nil {
				t.Fatalf("postheaders timeout added a response or hid truncation: %d %q %v", response.StatusCode, body, err)
			}
			response, err = client.Get(origin + "/stream")
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || strings.Count(string(body), "tick") != 6 || !strings.HasSuffix(string(body), "done") {
				t.Fatalf("active body timed out: %d %q %v", response.StatusCode, body, err)
			}
		})
	}
}
