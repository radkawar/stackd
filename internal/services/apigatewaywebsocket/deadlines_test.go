package apigatewaywebsocket_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"stackd/clock"
	"stackd/internal/services/apigatewayexec"
	"stackd/internal/services/apigatewaywebsocket"
)

// These durations are documented quotas, not native-captured close reasons:
// https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-execution-service-websocket-limits-table.html
func TestWebSocketDeadlines(t *testing.T) {
	for _, fixture := range []struct {
		name       string
		activityAt []time.Duration
		expiresAt  time.Duration
	}{
		{name: "idle", expiresAt: 10 * time.Minute},
		{name: "activity postpones idle", activityAt: []time.Duration{9 * time.Minute}, expiresAt: 19 * time.Minute},
		{
			name: "activity cannot postpone maximum lifetime",
			activityAt: []time.Duration{
				9 * time.Minute, 18 * time.Minute, 27 * time.Minute, 36 * time.Minute,
				45 * time.Minute, 54 * time.Minute, 63 * time.Minute, 72 * time.Minute,
				81 * time.Minute, 90 * time.Minute, 99 * time.Minute, 108 * time.Minute,
				117 * time.Minute,
			},
			expiresAt: 2 * time.Hour,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			_, manual, url := deadlineService(t)
			client := dialDeadlineSocket(t, url)
			start := manual.Now()
			advanceTo := func(elapsed time.Duration) {
				t.Helper()
				if err := manual.Advance(start.Add(elapsed).Sub(manual.Now())); err != nil {
					t.Fatal(err)
				}
			}
			for _, elapsed := range fixture.activityAt {
				advanceTo(elapsed)
				client.ping(t)
			}
			advanceTo(fixture.expiresAt - time.Nanosecond)
			// A quiet read checks survival without itself refreshing idle time.
			if err := client.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			_, err := ws.ReadFrame(client.reader)
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("socket did not remain quiet and open before deadline: %v", err)
			}
			advanceTo(fixture.expiresAt)
			frame := client.readFrame(t)
			if frame.Header.OpCode != ws.OpClose {
				t.Fatalf("deadline frame opcode = %v, want close", frame.Header.OpCode)
			}
			client.requireClosed(t)
		})
	}
}

func TestWebSocketServiceCloseTerminatesLiveSockets(t *testing.T) {
	service, _, url := deadlineService(t)
	clients := make([]*deadlineSocket, 3)
	for i := range clients {
		clients[i] = dialDeadlineSocket(t, url)
		clients[i].ping(t)
	}
	closeDeadlineService(t, service)
	for _, client := range clients {
		client.requireClosed(t)
	}
}

// No Lambda integration is installed: the handshake and control frames exercise
// the service's real HTTP/transport surface without simulating function results.
type deadlineResolver struct{}

func (deadlineResolver) ResolveWebSocket(_ context.Context, api, stage, _ string, _ []byte) (*apigatewayexec.Route, error) {
	if api != "deadline-api" || stage != "test" {
		return nil, apigatewayexec.ErrUnknownAPI
	}
	return &apigatewayexec.Route{
		Partition: "aws", AccountID: "111111111111", Region: "us-east-1",
		APIID: api, Stage: stage,
	}, nil
}

func deadlineService(t *testing.T) (*apigatewaywebsocket.Service, *clock.Manual, string) {
	t.Helper()
	manual := clock.NewManual(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	service := apigatewaywebsocket.New(apigatewaywebsocket.Config{Resolver: deadlineResolver{}, Clock: manual})
	handler := apigatewaywebsocket.NewHandler(service, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !handler.ServeExecution(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { closeDeadlineService(t, service) })
	return service, manual, "ws" + strings.TrimPrefix(server.URL, "http") + apigatewayexec.Prefix + "deadline-api/test"
}

func closeDeadlineService(t *testing.T, service *apigatewaywebsocket.Service) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- service.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Service.Close did not finish with live sockets")
	}
}

type deadlineSocket struct {
	conn   net.Conn
	reader io.Reader
}

func dialDeadlineSocket(t *testing.T, url string) *deadlineSocket {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, buffered, _, err := ws.Dial(ctx, url)
	if err != nil {
		t.Fatalf("WebSocket handshake: %v", err)
	}
	client := &deadlineSocket{conn: conn, reader: conn}
	if buffered != nil {
		client.reader = buffered
	}
	t.Cleanup(func() {
		_ = conn.Close()
		if buffered != nil {
			ws.PutReader(buffered)
		}
	})
	return client
}

func (c *deadlineSocket) readFrame(t *testing.T) ws.Frame {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := ws.ReadFrame(c.reader)
	if err != nil {
		t.Fatalf("reading WebSocket frame: %v", err)
	}
	return frame
}

func (c *deadlineSocket) ping(t *testing.T) {
	t.Helper()
	if err := c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := wsutil.WriteClientMessage(c.conn, ws.OpPing, []byte("activity")); err != nil {
		t.Fatal(err)
	}
	frame := c.readFrame(t)
	if frame.Header.OpCode != ws.OpPong || string(frame.Payload) != "activity" {
		t.Fatalf("ping response = %v %q, want matching pong", frame.Header.OpCode, frame.Payload)
	}
}

func (c *deadlineSocket) requireClosed(t *testing.T) {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Shutdown may send a close frame or close the transport directly.
	frame, err := ws.ReadFrame(c.reader)
	if errors.Is(err, io.EOF) {
		return
	}
	if err != nil || frame.Header.OpCode != ws.OpClose {
		t.Fatalf("waiting for socket closure: opcode %v, error %v", frame.Header.OpCode, err)
	}
	var b [1]byte
	if n, err := c.reader.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("peer socket read = %d, %v; want EOF after physical closure", n, err)
	}
}
