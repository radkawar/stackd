package elbv2

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"stackd/compute/elbv2/desync"
	api "stackd/internal/awsapi/elbv2"
)

func installedDesyncClassifier(t *testing.T) *desync.Classifier {
	t.Helper()
	executable := os.Getenv("STACKD_HTTP_DESYNC_GUARDIAN")
	if executable == "" {
		t.Skip("install the pinned native C adapter and set STACKD_HTTP_DESYNC_GUARDIAN to its absolute path")
	}
	classifier, err := desync.New(t.Context(), executable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = classifier.Close() })
	return classifier
}

type desyncTargetRequest struct {
	path, remoteAddress string
	close               bool
}

type desyncProxyHarness struct {
	service      *Service
	classifier   *desync.Classifier
	address      string
	secure       bool
	requests     atomic.Uint32
	completed    atomic.Uint32
	started      chan string
	targetClosed chan string
	observed     chan desyncTargetRequest
}

func nativeDesyncProxy(t *testing.T, secure bool) *desyncProxyHarness {
	t.Helper()
	h := &desyncProxyHarness{classifier: installedDesyncClassifier(t), secure: secure, started: make(chan string, 16), targetClosed: make(chan string, 16), observed: make(chan desyncTargetRequest, 16)}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		h.requests.Add(1)
		h.started <- request.URL.Path
		h.observed <- desyncTargetRequest{path: request.URL.Path, remoteAddress: request.RemoteAddr, close: request.Close}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return
		}
		h.completed.Add(1)
		if request.URL.Path == "/upgrade" {
			conn, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			if err := buffered.Flush(); err != nil {
				return
			}
			_, _ = io.Copy(conn, buffered)
			h.targetClosed <- conn.RemoteAddr().String()
			return
		}
		_, _ = io.WriteString(w, "target:"+request.URL.Path+":")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, string(body)+":"+request.Trailer.Get("X-Trailer"))
	}))
	backend.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			h.targetClosed <- conn.RemoteAddr().String()
		}
	}
	backend.Start()
	t.Cleanup(backend.Close)
	policy := newConnectionIdlePolicy(2 * time.Second)
	t.Cleanup(policy.close)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return policy.wrap(conn), nil
	}}
	t.Cleanup(transport.CloseIdleConnections)
	h.service = New(Config{Networks: controlNetwork{}, DesyncClassifier: h.classifier})
	t.Cleanup(func() { _ = h.service.Close() })
	scope := Scope{"aws", "000000000000", "us-east-1"}
	lbARN := arn(scope, "loadbalancer/app/desync/1")
	groupARN := arn(scope, "targetgroup/desync/2")
	listenerARN := arn(scope, "listener/app/desync/1/3")
	if err := h.service.repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutLoadBalancer(LoadBalancerRecord{Scope: scope, Data: api.LoadBalancer{LoadBalancerArn: new(api.LoadBalancerArn(lbARN)), AvailabilityZones: api.AvailabilityZones{{ZoneName: new(api.ZoneName("us-east-1a")), SubnetId: new(api.SubnetId("subnet-a"))}}}}); err != nil {
			return err
		}
		if err := tx.PutTargetGroup(TargetGroupRecord{Scope: scope, Data: api.TargetGroup{TargetGroupArn: new(api.TargetGroupArn(groupARN)), VpcId: new(api.VpcId("vpc-0aeae393af73839cf")), TargetType: new(api.TargetTypeEnum("ip")), Protocol: new(api.ProtocolEnum("HTTP")), LoadBalancerArns: api.LoadBalancerArns{api.LoadBalancerArn(lbARN)}}}); err != nil {
			return err
		}
		if err := tx.PutTarget(TargetRecord{Scope: scope, TargetGroupARN: groupARN, Data: api.TargetDescription{Id: new(api.TargetId("10.0.0.8")), Port: new(api.Port(8080))}, State: "healthy", Version: 1}); err != nil {
			return err
		}
		return tx.PutListener(ListenerRecord{Scope: scope, Data: api.Listener{ListenerArn: new(api.ListenerArn(listenerARN)), LoadBalancerArn: new(api.LoadBalancerArn(lbARN)), Protocol: new(api.ProtocolEnum("HTTP")), Port: new(api.Port(80)), DefaultActions: api.Actions{{Type: new(api.ActionTypeEnum("forward")), TargetGroupArn: new(api.TargetGroupArn(groupARN))}}}})
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.address = listener.Addr().String()
	wrapped := idleListener{Listener: listener, policy: policy, classifier: h.classifier}
	if secure {
		donor := httptest.NewTLSServer(http.NotFoundHandler())
		wrapped.tlsConfig = listenerTLSConfig(donor.TLS.Certificates[0])
		donor.Close()
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		h.service.runtime.serve(w, request, scope, listenerARN, &runtimeNode{transport: transport})
	}), ConnContext: idleHTTPContext, ConnState: idleHTTPState}
	go func() { _ = server.Serve(wrapped) }()
	t.Cleanup(func() { _ = server.Close() })
	return h
}

func (h *desyncProxyHarness) dial(t *testing.T) net.Conn {
	t.Helper()
	var conn net.Conn
	var err error
	if h.secure {
		conn, err = tls.Dial("tcp", h.address, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.Dial("tcp", h.address)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readDesyncResponse(t *testing.T, reader *bufio.Reader, status int, body string, closed bool) {
	t.Helper()
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != status || string(got) != body || response.Close != closed {
		t.Fatalf("response status=%d body=%q close=%v err=%v, want status=%d body=%q close=%v", response.StatusCode, got, response.Close, err, status, body, closed)
	}
}

func assertDesyncClientClosed(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("client did not close immediately after the complete response: %v", err)
	}
}

func TestNativeDesyncSevereAndParserFailureNeverForward(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, raw := range []string{
			"POST /severe HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nX",
			"POST /parser HTTP/1.1\r\nHost: alb.invalid\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
		} {
			t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[secure]+raw[5:12], func(t *testing.T) {
				h := nativeDesyncProxy(t, secure)
				conn := h.dial(t)
				if _, err := io.WriteString(conn, raw+"GET /must-not-forward HTTP/1.1\r\nHost: alb.invalid\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(conn)
				readDesyncResponse(t, reader, 400, "Bad Request", true)
				assertDesyncClientClosed(t, reader)
				if got := h.requests.Load(); got != 0 {
					t.Fatalf("severe/unframeable header forwarded %d requests", got)
				}
			})
		}
	}
}

func TestNativeDesyncAmbiguousCompletesAndClosesBothLegs(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[secure], func(t *testing.T) {
			h := nativeDesyncProxy(t, secure)
			conn := h.dial(t)
			// First prove this target is genuinely keepalive-capable: a normal
			// request is not closed, and the target socket remains open.
			reader := bufio.NewReader(conn)
			if _, err := io.WriteString(conn, "POST /keepalive HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 0\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			readDesyncResponse(t, reader, 200, "target:/keepalive::", false)
			baseline := <-h.observed
			if baseline.close || baseline.path != "/keepalive" {
				t.Fatalf("normal target request did not permit keepalive: %+v", baseline)
			}
			select {
			case address := <-h.targetClosed:
				t.Fatalf("normal target socket %s closed before the ambiguous request", address)
			default:
			}
			raw := "POST /ambiguous HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\nGET /must-not-forward HTTP/1.1\r\nHost: alb.invalid\r\n\r\n"
			if _, err := io.WriteString(conn, raw); err != nil {
				t.Fatal(err)
			}
			readDesyncResponse(t, reader, 200, "target:/ambiguous:data:", true)
			assertDesyncClientClosed(t, reader)
			observed := <-h.observed
			if !observed.close || observed.path != "/ambiguous" {
				t.Fatalf("ambiguous target request lacked real Close semantics: %+v", observed)
			}
			select {
			case address := <-h.targetClosed:
				if address != observed.remoteAddress {
					t.Fatalf("closed target socket %s was not ambiguous request socket %s", address, observed.remoteAddress)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("ambiguous request retained the real keepalive target connection")
			}
			if got := h.completed.Load(); got != 2 || h.requests.Load() != 2 {
				t.Fatalf("keepalive primer + ambiguous completed %d requests, total %d; pipelined request must not forward", got, h.requests.Load())
			}
		})
	}
}

func TestNativeDesyncStreamingChunksTrailersAndPipeline(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[secure], func(t *testing.T) {
			h := nativeDesyncProxy(t, secure)
			conn := h.dial(t)
			first := "POST /stream HTTP/1.1\r\nHost: alb.invalid\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n4;extension=kept\r\npart\r\n"
			if _, err := io.WriteString(conn, first); err != nil {
				t.Fatal(err)
			}
			select {
			case path := <-h.started:
				if path != "/stream" {
					t.Fatal(path)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("pre-parser buffered the body instead of streaming to the target")
			}
			if _, err := io.WriteString(conn, "4\r\ntwo!\r\n0\r\nX-Trailer: kept\r\n\r\nPOST /pipeline HTTP/1.1\r\nHost: alb.invalid\r\nContent-Length: 3\r\n\r\nend"); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			readDesyncResponse(t, reader, 200, "target:/stream:parttwo!:kept", false)
			readDesyncResponse(t, reader, 200, "target:/pipeline:end:", false)
			if got := h.completed.Load(); got != 2 {
				t.Fatalf("streaming/pipeline completed %d requests", got)
			}
		})
	}
}

func TestNativeDesyncBoundedFragmentedHeaders(t *testing.T) {
	h := nativeDesyncProxy(t, false)
	conn := h.dial(t)
	// A ReadSlice fragment consisting only of CRLF is NOT an empty header line
	// when it terminates a preceding 4096-byte fragment of the same long header.
	raw := "POST /long HTTP/1.1\r\nHost: alb.invalid\r\nX-Long: " + strings.Repeat("a", 4096-len("X-Long: ")) + "\r\nContent-Length: 1\r\n\r\nX"
	for _, fragment := range []string{raw[:17], raw[17:2050], raw[2050:]} {
		if _, err := io.WriteString(conn, fragment); err != nil {
			t.Fatal(err)
		}
	}
	readDesyncResponse(t, bufio.NewReader(conn), 200, "target:/long:X:", false)
	oversize := h.dial(t)
	if _, err := io.WriteString(oversize, "POST /large HTTP/1.1\r\nHost: alb.invalid\r\nX-Large: "+strings.Repeat("a", desync.MaxHeaderBytes)+"\r\n\r\n"); err != nil {
		// A TCP peer may observe the close while finishing the over-limit write.
		if failure, ok := err.(net.Error); ok && failure.Timeout() {
			t.Fatal(err)
		}
	}
	reader := bufio.NewReader(oversize)
	readDesyncResponse(t, reader, 400, "Bad Request", true)
	assertDesyncClientClosed(t, reader)
	if got := h.completed.Load(); got != 1 {
		t.Fatalf("over-limit header was forwarded: %d completed", got)
	}
}

func TestNativeDesyncMalformedChunkFailsClosed(t *testing.T) {
	h := nativeDesyncProxy(t, false)
	conn := h.dial(t)
	if _, err := io.WriteString(conn, "POST /chunk HTTP/1.1\r\nHost: alb.invalid\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n\r\nGET /must-not-forward HTTP/1.1\r\nHost: alb.invalid\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	readDesyncResponse(t, reader, 400, "Bad Request\n", true)
	assertDesyncClientClosed(t, reader)
	if got := h.completed.Load(); got != 0 {
		t.Fatalf("unframed body/pipeline completed %d target requests", got)
	}
}

func TestNativeDesyncAdmissionAndLibraryFailure(t *testing.T) {
	without := New(Config{})
	defer without.Close()
	if _, implemented, err := without.nativeLoadBalancerAttribute(t.Context(), "routing.http.desync_mitigation_mode"); implemented || err == nil || wireError(err).Code != "UnsupportedOperation" {
		t.Fatalf("nil classifier admitted defensive mode: implemented=%v err=%v", implemented, err)
	}
	if _, implemented, err := without.nativeDesyncAttribute(t.Context()); implemented || err != nil {
		t.Fatalf("nil classifier described a native mode: implemented=%v err=%v", implemented, err)
	}
	h := nativeDesyncProxy(t, true)
	if mode, implemented, err := h.service.nativeLoadBalancerAttribute(t.Context(), "routing.http.desync_mitigation_mode"); mode != "defensive" || !implemented || err != nil {
		t.Fatalf("healthy genuine classifier mode=%q implemented=%v err=%v", mode, implemented, err)
	}
	_ = h.classifier.Close()
	if _, implemented, err := h.service.nativeLoadBalancerAttribute(t.Context(), "routing.http.desync_mitigation_mode"); implemented || err == nil || wireError(err).Code != "UnsupportedOperation" {
		t.Fatalf("failed native library admitted mode: implemented=%v err=%v", implemented, err)
	}
	conn := h.dial(t)
	if _, err := io.WriteString(conn, "GET /no-library HTTP/1.1\r\nHost: alb.invalid\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	readDesyncResponse(t, reader, 400, "Bad Request", true)
	assertDesyncClientClosed(t, reader)
	if got := h.requests.Load(); got != 0 {
		t.Fatalf("unavailable native library forwarded %d requests", got)
	}
}
