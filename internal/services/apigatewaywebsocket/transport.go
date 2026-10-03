package apigatewaywebsocket

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"stackd/internal/awsctx"
)

type connection struct {
	service     *Service
	endpoint    endpoint
	id, domain  string
	identity    eventIdentity
	caller      awsctx.Metadata
	authorizer  map[string]json.RawMessage
	connectedAt time.Time
	socket      net.Conn
	ctx         context.Context
	cancel      context.CancelFunc
	writeGate   chan struct{}
	activity    chan struct{}
	closeOnce   sync.Once
	stateMu     sync.Mutex
	lastActive  time.Time
	closed      bool
	closedAt    time.Time
	closeCode   int
	closeReason string
}

func (c *connection) readMessages(source io.Reader) {
	defer c.service.workers.Done()
	defer c.disconnect()
	defer c.terminate(context.Background(), 1006, "Connection closed abnormally", false)
	reader := wsutil.Reader{Source: source, State: ws.StateServerSide, CheckUTF8: true, MaxFrameSize: maxFrameSize}
	reader.OnIntermediate = c.control
	for c.ctx.Err() == nil {
		header, err := reader.NextFrame()
		if err != nil {
			c.readFailure(err)
			return
		}
		if header.OpCode == ws.OpBinary {
			c.terminate(c.service.ctx, 1003, "Binary is not supported", true)
			return
		}
		if header.OpCode.IsControl() {
			if err := c.control(header, &reader); err != nil {
				c.readFailure(err)
				return
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(&reader, maxMessageSize+1))
		if err != nil {
			c.readFailure(err)
			return
		}
		if len(body) > maxMessageSize {
			c.terminate(c.service.ctx, 1009, "Message too big", true)
			return
		}
		c.touch()
		c.message(body)
	}
}

func (c *connection) control(header ws.Header, source io.Reader) error {
	// Reader has already checked the frame header and unmasked the payload.
	// Reading before acquiring the write gate prevents a partial control frame
	// from blocking Lambda/management responses on the same socket.
	payload, err := io.ReadAll(source)
	if err != nil {
		return err
	}
	handler := wsutil.ControlHandler{Src: bytes.NewReader(payload), Dst: io.Discard,
		State: ws.StateServerSide, DisableSrcCiphering: true}
	if header.OpCode == ws.OpClose {
		// The library validates close codes and UTF-8. We echo the complete
		// reason, matching API Gateway, rather than its default code-only echo.
		return handler.Handle(header)
	}
	// Inbound activity precedes its response, just as for data messages.
	c.touch()
	return c.withWriter(c.ctx, func(dst io.Writer) error {
		handler.Dst = dst
		return handler.Handle(header)
	})
}

func (c *connection) readFailure(err error) {
	var closed wsutil.ClosedError
	var protocol ws.ProtocolError
	switch {
	case errors.As(err, &closed):
		c.terminate(c.service.ctx, int(closed.Code), closed.Reason, true)
	case errors.Is(err, wsutil.ErrFrameTooLarge):
		c.terminate(c.service.ctx, 1009, "Message too big", true)
	case errors.Is(err, wsutil.ErrInvalidUTF8):
		c.terminate(c.service.ctx, 1007, "Invalid UTF-8", true)
	case errors.As(err, &protocol), errors.Is(err, ws.ErrHeaderLengthMSB), errors.Is(err, ws.ErrHeaderLengthUnexpected):
		c.terminate(c.service.ctx, 1002, "Protocol error", true)
	default:
		c.terminate(context.Background(), 1006, "Connection closed abnormally", false)
	}
}

func (c *connection) touch() {
	c.stateMu.Lock()
	if !c.closed {
		c.lastActive = c.service.clock.Now()
	}
	c.stateMu.Unlock()
	select {
	case c.activity <- struct{}{}:
	default:
	}
}

func (c *connection) expire() {
	defer c.service.workers.Done()
	for {
		c.stateMu.Lock()
		lastActive, closed := c.lastActive, c.closed
		c.stateMu.Unlock()
		if closed {
			return
		}
		deadline := lastActive.Add(idleTimeout)
		lifetime := c.connectedAt.Add(maxLifetime)
		if lifetime.Before(deadline) {
			deadline = lifetime
		}
		timer := c.service.clock.NewTimerAt(deadline)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return
		case <-c.activity:
			timer.Stop()
			continue
		case <-timer.C():
			timer.Stop()
		}
		// A timer firing may race real traffic. Decide against the latest
		// service time and activity, not a stale notification.
		c.stateMu.Lock()
		now, lastActive := c.service.clock.Now(), c.lastActive
		c.stateMu.Unlock()
		if !now.Before(lifetime) {
			c.terminate(c.service.ctx, 1001, "Connection duration exceeded", true)
			return
		}
		if !now.Before(lastActive.Add(idleTimeout)) {
			c.terminate(c.service.ctx, 1001, "Idle timeout", true)
			return
		}
	}
}

func (c *connection) terminate(ctx context.Context, code int, reason string, sendClose bool) {
	c.closeOnce.Do(func() {
		c.stateMu.Lock()
		c.closed, c.closeCode, c.closeReason = true, code, reason
		c.closedAt = c.service.clock.Now()
		c.stateMu.Unlock()
		c.cancel()
		c.service.mu.Lock()
		delete(c.service.connections, c.endpoint.connectionKey(c.id))
		c.service.mu.Unlock()
		if sendClose {
			_ = c.withWriter(ctx, func(dst io.Writer) error {
				if code == 1005 {
					return ws.WriteFrame(dst, ws.NewCloseFrame(nil))
				}
				return ws.WriteFrame(dst, ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusCode(code), reason)))
			})
		}
		_ = c.socket.Close()
	})
}

func (c *connection) withWriter(parent context.Context, write func(io.Writer) error) error {
	ctx, cancel := context.WithTimeout(parent, writeTimeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.writeGate:
	}
	defer func() { c.writeGate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := c.socket.SetWriteDeadline(deadline); err != nil {
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c.socket.SetWriteDeadline(time.Now())
		close(interrupted)
	})
	err := write(c.socket)
	if !stop() {
		<-interrupted
	}
	_ = c.socket.SetWriteDeadline(time.Time{})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (c *connection) sendText(ctx context.Context, payload []byte, metrics *eventMetrics) error {
	// Native management POST is always text. Invalid UTF-8 bytes become the
	// replacement character, not base64 and not a binary WebSocket frame.
	if !utf8.Valid(payload) {
		var replacement bytes.Buffer
		replacement.Grow(len(payload))
		for _, r := range string(payload) {
			_, _ = replacement.WriteRune(r)
		}
		payload = replacement.Bytes()
	}
	err := c.withWriter(ctx, func(dst io.Writer) error {
		c.stateMu.Lock()
		closed := c.closed
		c.stateMu.Unlock()
		if closed {
			return net.ErrClosed
		}
		// Native frame boundaries depend on its network buffering. Preserve the
		// observed text/continuation framing without promising exact chunks.
		op := ws.OpText
		for len(payload) > 8<<10 {
			if err := ws.WriteFrame(dst, ws.NewFrame(op, false, payload[:8<<10])); err != nil {
				return err
			}
			payload, op = payload[8<<10:], ws.OpContinuation
		}
		return ws.WriteFrame(dst, ws.NewFrame(op, true, payload))
	})
	if err == nil {
		c.touch()
		if metrics != nil {
			metrics.messages++
		}
	} else if metrics != nil {
		metrics.executionError = true
	}
	return err
}
