package stackd_test

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/gobwas/ws"
)

type gatewayMetricSocket struct {
	Label, Operation, Connection string
	StartedAt                    time.Time `json:"started_at"`
	Request                      struct {
		URL, Text   string
		Headers     map[string]string
		Opcode      ws.OpCode
		CloseCode   uint16 `json:"close_code"`
		CloseReason string `json:"close_reason"`
	}
	Result struct {
		Status                int
		Outcome, Text, Base64 string
		Opcode                ws.OpCode
		JSON                  map[string]any
		Body                  struct{ Base64 string }
	}
}

func (r *gatewayMetricReplay) socket(row gatewayMetricSocket) {
	t := r.t
	t.Helper()
	if row.Operation == "connect" {
		headers := http.Header{}
		for name, value := range row.Request.Headers {
			headers.Set(name, gatewayReplace(value, r.bindings))
		}
		socket, status, _, body, err := gatewayWSDial(t.Context(), r.localURL(row.Request.URL, true), headers)
		if status != row.Result.Status {
			if socket != nil {
				_ = socket.Close()
			}
			t.Fatalf("%s handshake=%d native=%d: %s (%v)", row.Label, status, row.Result.Status, body, err)
		}
		if status == http.StatusSwitchingProtocols {
			if err != nil {
				t.Fatal(err)
			}
			r.sockets[row.Connection] = socket
			return
		}
		if err == nil {
			t.Fatalf("%s unexpectedly upgraded a rejected connection", row.Label)
		}
		native, err := base64.StdEncoding.DecodeString(row.Result.Body.Base64)
		if err != nil {
			t.Fatal(err)
		}
		var expected map[string]any
		awsDecodeJSON(t, native, &expected)
		r.body(row.Label, expected, body)
		return
	}
	socket := r.sockets[row.Connection]
	if socket == nil {
		t.Fatalf("%s uses unopened connection %s", row.Label, row.Connection)
	}
	switch row.Operation {
	case "send":
		if err := socket.Send(row.Request.Opcode, []byte(gatewayReplace(row.Request.Text, r.bindings))); err != nil {
			t.Fatalf("%s: %v", row.Label, err)
		}
	case "receive":
		// This is a bounded socket witness, not a sleep to imitate AWS metric
		// publication. Two-way replies also bind IDs for later SDK callbacks.
		payload, opcode, err := socket.Read(2 * time.Second)
		if row.Result.Outcome == "timeout" {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("%s expected bounded silence, got opcode=%d payload=%s error=%v", row.Label, opcode, payload, err)
			}
			return
		}
		if err != nil || opcode != row.Result.Opcode {
			t.Fatalf("%s opcode=%d native=%d payload=%s error=%v", row.Label, opcode, row.Result.Opcode, payload, err)
		}
		if row.Result.JSON != nil {
			r.body(row.Label, row.Result.JSON, payload)
		} else if string(payload) != gatewayReplace(row.Result.Text, r.bindings) {
			t.Fatalf("%s payload=%q native=%q", row.Label, payload, row.Result.Text)
		}
	case "close":
		if err := socket.Send(ws.OpClose, ws.NewCloseFrameBody(ws.StatusCode(row.Request.CloseCode), row.Request.CloseReason)); err != nil {
			t.Fatalf("%s: %v", row.Label, err)
		}
		payload, opcode, err := socket.Read(2 * time.Second)
		expected, decodeErr := base64.StdEncoding.DecodeString(row.Result.Base64)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if err != nil || opcode != row.Result.Opcode || !reflect.DeepEqual(payload, expected) {
			t.Fatalf("%s close opcode=%d payload=%q native=%q error=%v", row.Label, opcode, payload, expected, err)
		}
		_ = socket.Close()
		delete(r.sockets, row.Connection)
	default:
		t.Fatalf("%s unsupported native socket operation %s", row.Label, row.Operation)
	}
}
