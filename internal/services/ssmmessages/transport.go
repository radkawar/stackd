package ssmmessages

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/google/uuid"
)

const (
	handshakeTimeout = 30 * time.Second
	writeTimeout     = 5 * time.Second
	deliveryInterval = 100 * time.Millisecond
)

type connection struct {
	service  *Service
	owner    tokenOwner
	slot     *nodeSlot
	socket   net.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	writeMu  sync.Mutex
	stopOnce sync.Once
	ready    bool // read-loop owned; pending worker starts only after handshake
}

func (s *Service) open(w http.ResponseWriter, r *http.Request, owner tokenOwner) {
	upgrader := ws.HTTPUpgrader{Timeout: writeTimeout}
	socket, buffered, _, err := upgrader.Upgrade(r, w)
	if err != nil {
		if socket != nil {
			_ = socket.Close()
		}
		return
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	c := &connection{service: s, owner: owner, socket: socket, ctx: ctx, cancel: cancel}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.stop()
		return
	}
	slot := s.slots[owner.nodeKey]
	if slot == nil {
		slot = &nodeSlot{}
		s.slots[owner.nodeKey] = slot
	}
	slot.refs++
	c.slot = slot
	s.connections[c] = struct{}{}
	s.workers.Add(1)
	s.mu.Unlock()
	go c.run(buffered.Reader)
}

func (c *connection) stop() { c.stopOnce.Do(func() { c.cancel(); _ = c.socket.Close() }) }

func (c *connection) run(source io.Reader) {
	var workers sync.WaitGroup
	defer c.service.workers.Done()
	defer func() {
		c.stop()
		workers.Wait()
		c.slot.mu.Lock()
		if c.slot.current == c {
			c.slot.current = nil
		}
		c.slot.mu.Unlock()
		c.service.mu.Lock()
		delete(c.service.connections, c)
		c.slot.refs--
		if c.slot.refs == 0 {
			delete(c.service.slots, c.owner.nodeKey)
		}
		c.service.mu.Unlock()
	}()
	if err := c.socket.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}
	reader := wsutil.Reader{Source: source, State: ws.StateServerSide, CheckUTF8: true, MaxFrameSize: maxMessageSize}
	reader.OnIntermediate = c.control
	for c.ctx.Err() == nil {
		header, err := reader.NextFrame()
		if err != nil {
			c.fail(err)
			return
		}
		if header.OpCode.IsControl() {
			if err := c.control(header, &reader); err != nil {
				c.fail(err)
				return
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(&reader, maxMessageSize+1))
		if err != nil {
			c.fail(err)
			return
		}
		if len(body) > maxMessageSize {
			c.closeFrame(1009, "Agent message exceeds transport limit")
			return
		}
		if !c.ready {
			if header.OpCode != ws.OpText {
				c.closeFrame(1002, "Expected control channel token handshake")
				return
			}
			if err := c.handshake(body); err != nil {
				c.fail(err)
				return
			}
			c.ready = true
			if err := c.socket.SetReadDeadline(time.Time{}); err != nil {
				return
			}
			workers.Add(1)
			go func() { defer workers.Done(); c.deliver() }()
			continue
		}
		if header.OpCode != ws.OpBinary {
			c.closeFrame(1003, "Expected binary agent message")
			return
		}
		message, err := decodeMessage(body)
		if err == nil {
			err = c.receive(message)
		}
		if err != nil {
			c.fail(err)
			return
		}
	}
}

func (c *connection) handshake(body []byte) error {
	var input channelInput
	if len(body) > 16<<10 || json.Unmarshal(body, &input) != nil || input.MessageSchemaVersion != "1.0" || len(input.RequestID) < 16 || input.AgentVersion == "" || input.PlatformType == "" {
		return errors.New("invalid control channel handshake")
	}
	c.slot.mu.Lock()
	defer c.slot.mu.Unlock()
	if err := c.authorize(); err != nil {
		return err
	}
	if !c.service.consumeToken(input.TokenValue, c.owner) {
		return errors.New("invalid or expired control channel token")
	}
	// The native agent mints its token after the WebSocket dial. Only a complete,
	// authorized token handshake replaces a previously subscribed connection.
	if old := c.slot.current; old != nil {
		old.stop()
	}
	c.slot.current = c
	return nil
}

func (c *connection) authorize() error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	return c.service.backend.AuthorizeAgent(c.ctx, c.owner.node, openAction)
}

func (c *connection) current() error {
	if c.slot.current != c {
		return errors.New("control channel replaced")
	}
	return c.authorize()
}

func (c *connection) receive(message Message) error {
	c.slot.mu.Lock()
	defer c.slot.mu.Unlock()
	if err := c.current(); err != nil {
		return err
	}
	switch message.Type {
	case "agent_job_ack":
		return c.service.backend.ReceiveMessage(c.ctx, c.owner.node, message)
	case "agent_job_reply":
		var reply struct {
			JobID         string `json:"jobId"`
			SchemaVersion int    `json:"schemaVersion"`
		}
		if err := json.Unmarshal(message.Payload, &reply); err != nil {
			return fmt.Errorf("invalid agent job reply: %w", err)
		}
		if reply.JobID == "" || reply.SchemaVersion != 1 {
			return errors.New("invalid agent job reply schema or job ID")
		}
		if err := c.service.backend.ReceiveMessage(c.ctx, c.owner.node, message); err != nil {
			return err
		}
		// Upstream AgentJobReplyAckContent uses these exact lower-camel-case keys.
		payload, err := json.Marshal(struct {
			JobID                 string `json:"jobId"`
			AcknowledgedMessageID string `json:"acknowledgedMessageId"`
		}{reply.JobID, message.ID.String()})
		if err != nil {
			return err
		}
		if err := c.current(); err != nil {
			return err
		}
		return c.send(Message{ID: uuid.New(), Type: "agent_job_reply_ack", CreatedAt: c.service.clock.Now(), Payload: payload})
	case "agent_telemetry", "agent_telemetry_v2", "agent_update_result":
		if !json.Valid(message.Payload) {
			return errors.New("invalid agent telemetry payload")
		}
		// TODO: Comeback persist/export native agent telemetry. These best-effort
		// frames have no ACK and must never advance a managed command's outcome.
		return nil
	default:
		// TODO: Comeback implement Session Manager control messages alongside the
		// session owner, rather than acknowledging unexecuted sessions or tasks.
		return fmt.Errorf("unsupported control channel message type %q", message.Type)
	}
}

func (c *connection) deliver() {
	ticker := time.NewTicker(deliveryInterval)
	defer ticker.Stop()
	for {
		if err := c.pending(); err != nil {
			c.fail(err)
			c.stop()
			return
		}
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *connection) pending() error {
	c.slot.mu.Lock()
	defer c.slot.mu.Unlock()
	if err := c.current(); err != nil {
		return err
	}
	messages, err := c.service.backend.PendingMessages(c.ctx, c.owner.node)
	if err != nil {
		return err
	}
	for _, message := range messages {
		if err := c.current(); err != nil {
			return err
		}
		if message.Type != "agent_job" {
			return fmt.Errorf("unsupported pending control message type %q", message.Type)
		}
		if err := c.send(message); err != nil {
			return err
		}
	}
	return nil
}

func (c *connection) send(message Message) error {
	body, err := encodeMessage(message)
	if err != nil {
		return err
	}
	return c.write(ws.OpBinary, body)
}

func (c *connection) write(op ws.OpCode, body []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if err := c.socket.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return wsutil.WriteServerMessage(c.socket, op, body)
}

func (c *connection) control(header ws.Header, source io.Reader) error {
	payload, err := io.ReadAll(source)
	if err != nil {
		return err
	}
	handler := wsutil.ControlHandler{Src: bytes.NewReader(payload), Dst: io.Discard, State: ws.StateServerSide, DisableSrcCiphering: true}
	if err := handler.Handle(header); err != nil {
		return err
	}
	c.slot.mu.Lock()
	defer c.slot.mu.Unlock()
	if c.ready {
		err = c.current()
	} else {
		err = c.authorize()
	}
	if err != nil {
		return err
	}
	if header.OpCode == ws.OpPing {
		return c.write(ws.OpPong, payload)
	}
	return nil
}

func (c *connection) fail(err error) {
	var closed wsutil.ClosedError
	if errors.As(err, &closed) {
		c.closeFrame(closed.Code, closed.Reason)
		return
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return
	}
	slog.WarnContext(c.ctx, "SSM agent control channel failed", "instance_id", c.owner.node, "error", err)
	c.closeFrame(ws.StatusPolicyViolation, err.Error())
}

func (c *connection) closeFrame(code ws.StatusCode, reason string) {
	if len(reason) > 123 {
		reason = reason[:123]
	}
	for !utf8.ValidString(reason) {
		reason = reason[:len(reason)-1]
	}
	_ = c.write(ws.OpClose, ws.NewCloseFrameBody(code, reason))
}
