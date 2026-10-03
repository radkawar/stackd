package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The bridge has no telemetry backlog. Each producer transfers one command to
// PID 1 and waits until that process owns its bytes. Subscription queues, init
// history and retry payloads exist only in the resource-limited container.
type telemetryBridge struct {
	ctx     context.Context
	cancel  context.CancelFunc
	path    string
	calls   chan *telemetryCall
	ready   chan struct{}
	once    sync.Once
	mu      sync.Mutex
	next    uint64
	pending map[uint64]*telemetryCall
	output  func([]byte, bool, bool)
}

type telemetryCommand struct {
	ID               uint64
	Operation        string
	Name, Path, Kind string
	At               time.Time
	Body             json.RawMessage
}

type telemetryReply struct {
	ID     uint64
	Status int
	Body   json.RawMessage
	Error  string
}

type telemetryCall struct {
	command telemetryCommand
	reply   chan telemetryReply
}

func newTelemetryBridge(ctx context.Context) *telemetryBridge {
	ctx, cancel := context.WithCancel(ctx)
	return &telemetryBridge{ctx: ctx, cancel: cancel, path: "/internal/telemetry/" + newRuntimeID(), calls: make(chan *telemetryCall), ready: make(chan struct{}), pending: make(map[uint64]*telemetryCall)}
}

func (b *telemetryBridge) call(ctx context.Context, command telemetryCommand) (telemetryReply, error) {
	b.mu.Lock()
	b.next++
	command.ID = b.next
	call := &telemetryCall{command: command, reply: make(chan telemetryReply, 1)}
	b.pending[command.ID] = call
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.pending, command.ID); b.mu.Unlock() }()
	select {
	case b.calls <- call:
	case <-ctx.Done():
		return telemetryReply{}, ctx.Err()
	case <-b.ctx.Done():
		return telemetryReply{}, b.ctx.Err()
	}
	select {
	case reply := <-call.reply:
		if reply.Error != "" {
			return reply, fmt.Errorf("lambda telemetry helper: %s", reply.Error)
		}
		return reply, nil
	case <-ctx.Done():
		return telemetryReply{}, ctx.Err()
	case <-b.ctx.Done():
		return telemetryReply{}, b.ctx.Err()
	}
}

func (b *telemetryBridge) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == b.path+"/output" {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, telemetryLineChunk+1))
		if err != nil {
			http.Error(w, "invalid helper output", http.StatusBadRequest)
			return
		}
		b.output(body, r.Header.Get("X-Stackd-Log-Deliver") == "true", r.Header.Get("X-Stackd-Log-Capture") == "true")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == b.path {
		b.once.Do(func() { close(b.ready) })
		select {
		case call := <-b.calls:
			writeRuntimeJSON(w, http.StatusOK, call.command)
		case <-b.ctx.Done():
			http.Error(w, "helper closed", http.StatusGone)
		case <-r.Context().Done():
		}
		return
	}
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, b.path+"/") {
		id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, b.path+"/"), 10, 64)
		var reply telemetryReply
		if err != nil || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&reply) != nil || reply.ID != id {
			http.Error(w, "invalid helper reply", http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		call := b.pending[id]
		b.mu.Unlock()
		if call != nil {
			select {
			case call.reply <- reply:
			default:
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.NotFound(w, r)
}
