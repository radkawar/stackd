package ssmmessages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/google/uuid"
	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
)

const testNode = "i-0123456789abcdef0"

type testBackend struct {
	mu            sync.Mutex
	denied        atomic.Bool
	pending       []Message
	replies       []Message
	receiveErr    error
	commitStarted chan struct{}
	commitRelease chan struct{}
}

func (b *testBackend) AuthorizeAgent(ctx context.Context, node, action string) error {
	m := awsctx.FromContext(ctx)
	if b.denied.Load() || m.AccountID != "000000000000" || m.Region != "us-east-1" || node != testNode {
		return &awswire.Error{Code: "AccessDeniedException", Message: "node authority revoked", StatusCode: 403}
	}
	return nil
}
func (b *testBackend) PendingMessages(context.Context, string) ([]Message, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Message(nil), b.pending...), nil
}
func (b *testBackend) ReceiveMessage(ctx context.Context, _ string, m Message) error {
	if b.commitStarted != nil {
		close(b.commitStarted)
		select {
		case <-b.commitRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.receiveErr != nil {
		return b.receiveErr
	}
	b.replies = append(b.replies, m)
	if m.Type == "agent_job_ack" {
		b.pending = nil
	}
	return nil
}

type harness struct {
	service *Service
	server  *httptest.Server
	backend *testBackend
	clock   *clock.Manual
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	g, err := gateway.New(&gateway.Registry{}, gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	b := &testBackend{}
	clk := clock.NewManual(time.Now())
	s := New(Config{Backend: b, Authenticate: g.Authenticate, Clock: clk})
	server := httptest.NewServer(s)
	t.Cleanup(func() { _ = s.Close(); server.Close() })
	return &harness{s, server, b, clk}
}
func signedRequest(t *testing.T, method, endpoint, region, key, secret string, body []byte) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}, r, hex.EncodeToString(digest[:]), "ssmmessages", region, time.Now()); err != nil {
		t.Fatal(err)
	}
	return r
}
func (h *harness) token(t *testing.T) string {
	t.Helper()
	body := []byte(`{"MessageSchemaVersion":"1.0","RequestId":"` + uuid.NewString() + `"}`)
	r := signedRequest(t, "POST", h.server.URL+"/v1/control-channel/"+testNode, "us-east-1", "test", "test", body)
	response, err := h.server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 201 {
		b, _ := io.ReadAll(response.Body)
		t.Fatalf("create: %d %s", response.StatusCode, b)
	}
	var reply struct {
		TokenValue           string `xml:"TokenValue"`
		MessageSchemaVersion string `xml:"MessageSchemaVersion"`
	}
	if err := xml.NewDecoder(response.Body).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	if reply.TokenValue == "" || reply.MessageSchemaVersion != "1.0" {
		t.Fatal("invalid native token response")
	}
	return reply.TokenValue
}
func (h *harness) dial(t *testing.T) net.Conn {
	t.Helper()
	return h.dialAs(t, "test")
}
func (h *harness) dialAs(t *testing.T, key string) net.Conn {
	t.Helper()
	endpoint := h.server.URL + "/v1/control-channel/" + testNode + "?role=subscribe&stream=input"
	r := signedRequest(t, "GET", endpoint, "us-east-1", key, "test", nil)
	dialer := ws.Dialer{Header: ws.HandshakeHeaderHTTP(r.Header), Timeout: time.Second}
	conn, _, _, err := dialer.Dial(t.Context(), "ws"+strings.TrimPrefix(endpoint, "http"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
func handshake(t *testing.T, conn net.Conn, token string) {
	t.Helper()
	body, err := json.Marshal(channelInput{MessageSchemaVersion: "1.0", RequestID: uuid.NewString(), TokenValue: token, AgentVersion: "3.3.999.0", PlatformType: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	if err := wsutil.WriteClientMessage(conn, ws.OpText, body); err != nil {
		t.Fatal(err)
	}
}
func frame(t *testing.T, conn net.Conn) ws.Frame {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	f, err := ws.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func ping(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := wsutil.WriteClientMessage(conn, ws.OpPing, []byte("keepalive")); err != nil {
		t.Fatal(err)
	}
	f := frame(t, conn)
	if f.Header.OpCode != ws.OpPong || string(f.Payload) != "keepalive" {
		t.Fatalf("pong: %v %s", f.Header, f.Payload)
	}
}
func send(t *testing.T, conn net.Conn, m Message) {
	t.Helper()
	b, err := encodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := wsutil.WriteClientMessage(conn, ws.OpBinary, b); err != nil {
		t.Fatal(err)
	}
}
func requireClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := ws.ReadFrame(conn)
	if err == nil && f.Header.OpCode != ws.OpClose {
		t.Fatalf("connection still delivered %s", f.Payload)
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("connection failed to close")
	}
}

func TestSignedScopeRejectsSpoofedIdentityAndTampering(t *testing.T) {
	h := newHarness(t)
	body := []byte(`{"MessageSchemaVersion":"1.0","RequestId":"1234567890123456"}`)
	for _, test := range []struct {
		name, region, key, secret string
		unsigned                  bool
		want                      int
	}{
		{"unsigned", "us-east-1", "test", "test", true, 400},
		{"wrong-secret", "us-east-1", "test", "wrong", false, 403},
		{"wrong-account", "us-east-1", "123456789012", "test", false, 403},
		{"wrong-region", "us-west-2", "test", "test", false, 403},
		{"malformed-region", "us-east-1/extra", "test", "test", false, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := signedRequest(t, "POST", h.server.URL+"/v1/control-channel/"+testNode, test.region, test.key, test.secret, body)
			if test.unsigned {
				r.Header.Del("Authorization")
			}
			r.Header.Set("X-Stackd-Account-Id", "000000000000")
			r.Header.Set("X-Amz-Region", "us-east-1")
			r.Header.Set("X-Stackd-Principal-Arn", "arn:aws:iam::000000000000:root")
			resp, err := h.server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != test.want {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status %d: %s", resp.StatusCode, b)
			}
		})
	}
}

func TestPostDialTokenOneUseExpiryAndScope(t *testing.T) {
	h := newHarness(t)
	first := h.dial(t) // official current order: signed dial, mint, text handshake
	token := h.token(t)
	handshake(t, first, token)
	ping(t, first)
	replay := h.dial(t)
	handshake(t, replay, token)
	requireClosed(t, replay)
	ping(t, first) // a rejected handshake does not replace the current subscriber
	expired := h.dial(t)
	token = h.token(t)
	if err := h.clock.Advance(tokenLifetime); err != nil {
		t.Fatal(err)
	}
	handshake(t, expired, token)
	requireClosed(t, expired)
	token = h.token(t)
	mismatch := h.dialAs(t, "000000000000") // same principal, different access key
	handshake(t, mismatch, token)
	requireClosed(t, mismatch)
}

func TestReconnectFencesOldDeliveryAndRetainsMessageID(t *testing.T) {
	h := newHarness(t)
	first := h.dial(t)
	handshake(t, first, h.token(t))
	ping(t, first)
	second := h.dial(t)
	handshake(t, second, h.token(t))
	ping(t, second)
	requireClosed(t, first)
	job := Message{ID: uuid.New(), Type: "agent_job", CreatedAt: h.clock.Now(), Payload: []byte(`{"JobId":"job"}`)}
	h.backend.mu.Lock()
	h.backend.pending = []Message{job}
	h.backend.mu.Unlock()
	for range 2 {
		f := frame(t, second)
		got, err := decodeMessage(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if f.Header.OpCode != ws.OpBinary || got.ID != job.ID || !bytes.Equal(got.Payload, job.Payload) {
			t.Fatalf("changed redelivery: %+v", got)
		}
	}
	h.backend.denied.Store(true)
	requireClosed(t, second)
}

func TestReplyAckOnlyAfterCommitAndTelemetryIsNotCommandSuccess(t *testing.T) {
	h := newHarness(t)
	h.backend.commitStarted = make(chan struct{})
	h.backend.commitRelease = make(chan struct{})
	conn := h.dial(t)
	handshake(t, conn, h.token(t))
	ping(t, conn)
	telemetry := Message{ID: uuid.New(), Type: "agent_telemetry_v2", CreatedAt: h.clock.Now(), Payload: []byte(`{"SchemaVersion":1}`)}
	send(t, conn, telemetry)
	ping(t, conn)
	h.backend.mu.Lock()
	count := len(h.backend.replies)
	h.backend.mu.Unlock()
	if count != 0 {
		t.Fatal("telemetry committed a command reply")
	}
	reply := Message{ID: uuid.New(), Type: "agent_job_reply", CreatedAt: h.clock.Now(), Payload: []byte(`{"jobId":"aws.ssm.command.node","schemaVersion":1,"content":"{}","topic":"aws.ssm.sendCommand"}`)}
	send(t, conn, reply)
	select {
	case <-h.backend.commitStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("reply did not reach commit")
	}
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := ws.ReadFrame(conn); err == nil {
		t.Fatal("reply acknowledged before commit")
	} else {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal(err)
		}
	}
	close(h.backend.commitRelease)
	f := frame(t, conn)
	ack, err := decodeMessage(f.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	if err := json.Unmarshal(ack.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if ack.Type != "agent_job_reply_ack" || len(payload) != 2 || payload["jobId"] != "aws.ssm.command.node" || payload["acknowledgedMessageId"] != reply.ID.String() {
		t.Fatalf("incorrect native ACK: %+v %s", ack, ack.Payload)
	}
	h.backend.mu.Lock()
	count = len(h.backend.replies)
	h.backend.mu.Unlock()
	if count != 1 {
		t.Fatalf("committed replies=%d", count)
	}
}

func TestCommitFailureAndRevocationNeverAcknowledgeReply(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit-failure", true: "revoked"}[revoke], func(t *testing.T) {
			h := newHarness(t)
			h.backend.receiveErr = errors.New("durable reply commit failed")
			conn := h.dial(t)
			handshake(t, conn, h.token(t))
			ping(t, conn)
			h.backend.denied.Store(revoke)
			send(t, conn, Message{ID: uuid.New(), Type: "agent_job_reply", CreatedAt: h.clock.Now(), Payload: []byte(`{"jobId":"job","schemaVersion":1}`)})
			f := frame(t, conn)
			if f.Header.OpCode != ws.OpClose {
				t.Fatal("failed reply was acknowledged")
			}
			want := "durable reply commit failed"
			if revoke {
				want = "node authority revoked"
			}
			if !bytes.Contains(f.Payload, []byte(want)) {
				t.Fatalf("lost backend failure: %q", f.Payload)
			}
		})
	}
}

func TestCloseJoinsPendingAndSubscribedConnections(t *testing.T) {
	h := newHarness(t)
	pending := h.dial(t)
	subscribed := h.dial(t)
	handshake(t, subscribed, h.token(t))
	ping(t, subscribed)
	done := make(chan struct{})
	go func() { _ = h.service.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close left workers running")
	}
	requireClosed(t, pending)
	requireClosed(t, subscribed)
	h.service.mu.Lock()
	remaining := len(h.service.connections)
	h.service.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("connections after Close: %d", remaining)
	}
}
