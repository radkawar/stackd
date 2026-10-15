package elbv2

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"

	"stackd/compute/elbv2/desync"
)

type desyncFrame uint8

const (
	desyncHeader desyncFrame = iota
	desyncFixedBody
	desyncChunkLine
	desyncChunkBody
	desyncChunkEnd
	desyncTrailers
	desyncBoundary
)

// desyncConnection gates the ORIGINAL header bytes before net/http can trim,
// combine, unfold or discard them. Only framing is parsed in Go, after the native
// library verdict. Bodies remain streamed as wire bytes, including chunk syntax.
// Reads never span a request boundary: prefetched pipeline bytes stay private.
type desyncConnection struct {
	net.Conn
	classifier *desync.Classifier
	idle       *idleConnection
	reader     *bufio.Reader
	ctx        context.Context
	cancel     context.CancelFunc
	readMu     sync.Mutex
	frame      desyncFrame
	remaining  uint64
	pending    []byte
	scratch    []byte
	mu         sync.Mutex
	wake       chan struct{}
	permit     bool
	closed     bool
	tunnel     bool
	deadline   time.Time
	verdict    desync.Verdict
	bodyError  error
}

func newDesyncConnection(conn net.Conn, classifier *desync.Classifier, idle *idleConnection) *desyncConnection {
	ctx, cancel := context.WithCancel(context.Background())
	return &desyncConnection{Conn: conn, classifier: classifier, idle: idle, reader: bufio.NewReaderSize(conn, 4096), ctx: ctx, cancel: cancel, frame: desyncHeader, permit: true, wake: make(chan struct{}, 1), scratch: make([]byte, 0, 4096)}
}

func (c *desyncConnection) notifyLocked() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// net/http starts a background socket read during a response. Holding the next
// request at this gate prevents a pipelined severe request from racing a 400
// against the current response. Its abortPendingRead deadline still interrupts
// the gate, allowing net/http to finish the response and enter StateIdle.
func (c *desyncConnection) waitForRequest() error {
	for {
		c.mu.Lock()
		closed, deadline, permit, wake := c.closed, c.deadline, c.permit, c.wake
		c.mu.Unlock()
		if closed {
			return net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		if permit {
			return nil
		}
		if c.reader.Buffered() == 0 {
			// Keep net/http's real disconnect detection during target work. A
			// received byte stays private until StateIdle; it is never returned
			// as an unclassified pipelined request. Read deadlines interrupt Peek.
			if _, err := c.reader.Peek(1); err != nil {
				return err
			}
			continue
		}
		if deadline.IsZero() {
			select {
			case <-wake:
			case <-c.ctx.Done():
				return net.ErrClosed
			}
			continue
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-timer.C:
			return os.ErrDeadlineExceeded
		case <-wake:
			timer.Stop()
		case <-c.ctx.Done():
			timer.Stop()
			return net.ErrClosed
		}
	}
}

func (c *desyncConnection) completeRequest(hijacked bool) {
	c.mu.Lock()
	c.permit, c.tunnel = true, hijacked
	c.notifyLocked()
	c.mu.Unlock()
}

func (c *desyncConnection) ambiguous() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.verdict.Tier == desync.Ambiguous
}

// A body parser failure is available to the proxy ErrorHandler. It must return
// 400 with Connection: close; never forward the remaining unframed bytes.
func (c *desyncConnection) protocolFailure() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bodyError != nil
}

func (c *desyncConnection) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.notifyLocked()
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(deadline)
}

func (c *desyncConnection) SetDeadline(deadline time.Time) error {
	return errors.Join(c.SetReadDeadline(deadline), c.Conn.SetWriteDeadline(deadline))
}

func (c *desyncConnection) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.cancel()
		c.notifyLocked()
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *desyncConnection) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}

func (c *desyncConnection) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		c.mu.Lock()
		bodyError, tunnel, closed := c.bodyError, c.tunnel, c.closed
		c.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		if bodyError != nil {
			return 0, bodyError
		}
		if tunnel {
			return c.reader.Read(out)
		}
		if len(c.pending) != 0 {
			n := copy(out, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
		switch c.frame {
		case desyncBoundary:
			if err := c.waitForRequest(); err != nil {
				return 0, err
			}
			c.mu.Lock()
			tunnel := c.tunnel
			c.mu.Unlock()
			if tunnel {
				continue
			}
			c.frame = desyncHeader
		case desyncHeader:
			if err := c.readHeader(); err != nil {
				return 0, err
			}
		case desyncFixedBody, desyncChunkBody:
			limit := uint64(len(out))
			if limit > c.remaining {
				limit = c.remaining
			}
			n, err := c.reader.Read(out[:int(limit)])
			c.remaining -= uint64(n)
			if c.remaining == 0 {
				if c.frame == desyncChunkBody {
					c.frame = desyncChunkEnd
				} else {
					c.frame = desyncBoundary
				}
			}
			if errors.Is(err, io.EOF) && c.remaining != 0 {
				err = c.failBody(io.ErrUnexpectedEOF)
			}
			return n, err
		case desyncChunkLine:
			line, err := c.readLine(4096)
			if err != nil {
				return 0, c.failBody(err)
			}
			size := bytes.TrimRight(line, " \t\r\n")
			if semicolon := bytes.IndexByte(size, ';'); semicolon >= 0 {
				size = size[:semicolon]
			}
			if len(size) == 0 || len(size) > 16 {
				return 0, c.failBody(errors.New("invalid chunk size"))
			}
			for _, ch := range size {
				if !('0' <= ch && ch <= '9' || 'a' <= ch && ch <= 'f' || 'A' <= ch && ch <= 'F') {
					return 0, c.failBody(errors.New("invalid chunk size"))
				}
			}
			n, err := strconv.ParseUint(string(size), 16, 64)
			if err != nil {
				return 0, c.failBody(err)
			}
			c.pending, c.remaining = line, n
			if n == 0 {
				c.frame = desyncTrailers
			} else {
				c.frame = desyncChunkBody
			}
		case desyncChunkEnd:
			var ending [2]byte
			if _, err := io.ReadFull(c.reader, ending[:]); err != nil {
				return 0, c.failBody(err)
			}
			if ending != [2]byte{'\r', '\n'} {
				return 0, c.failBody(errors.New("invalid chunk data terminator"))
			}
			c.scratch = append(c.scratch[:0], ending[:]...)
			c.pending, c.frame = c.scratch, desyncChunkLine
		case desyncTrailers:
			block, err := c.readBlock(desync.MaxHeaderBytes)
			if err != nil {
				return 0, c.failBody(err)
			}
			if _, err = textproto.NewReader(bufio.NewReader(bytes.NewReader(block))).ReadMIMEHeader(); err != nil {
				return 0, c.failBody(err)
			}
			c.pending, c.frame = block, desyncBoundary
		}
	}
}

func (c *desyncConnection) readHeader() error {
	if err := c.waitForRequest(); err != nil {
		return err
	}
	if c.idle != nil && c.reader.Buffered() != 0 {
		c.idle.policy.mu.Lock()
		c.idle.input = true
		c.idle.policy.mu.Unlock()
	}
	raw, err := c.readBlock(desync.MaxHeaderBytes)
	if err != nil {
		if len(raw) == 0 && errors.Is(err, io.EOF) {
			return err
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return err // Existing idle policy owns the incomplete-header HTTP 408.
		}
		return c.rejectHeader(err)
	}
	verdict, err := c.classifier.Classify(c.ctx, raw)
	if err != nil {
		return c.rejectHeader(err)
	}
	if verdict.Tier == desync.Severe {
		return c.rejectHeader(errors.New("native guardian classified the request as severe"))
	}
	// This is NOT classification. net/http is the downstream framing parser;
	// reject anything it cannot frame, rather than inventing normalization rules.
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return c.rejectHeader(err)
	}
	if request.ProtoMajor != 1 {
		return c.rejectHeader(errors.New("native guardian listener only supports HTTP/1"))
	}
	for name, values := range request.Header {
		if !httpguts.ValidHeaderFieldName(name) {
			return c.rejectHeader(errors.New("invalid HTTP header name"))
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return c.rejectHeader(errors.New("invalid HTTP header value"))
			}
		}
	}
	c.mu.Lock()
	c.verdict, c.permit = verdict, false
	c.mu.Unlock()
	c.pending = raw
	if len(request.TransferEncoding) != 0 {
		c.frame = desyncChunkLine
	} else if request.ContentLength > 0 {
		c.remaining, c.frame = uint64(request.ContentLength), desyncFixedBody
	} else {
		c.frame = desyncBoundary
	}
	return nil
}

// readBlock retains every original byte, including LF-only endings and obs-fold.
// The same fixed bound applies to raw headers and chunked trailers.
func (c *desyncConnection) readBlock(limit int) ([]byte, error) {
	c.scratch = c.scratch[:0]
	lineBytes := 0
	for len(c.scratch) < limit {
		line, err := c.reader.ReadSlice('\n')
		if len(line) > limit-len(c.scratch) {
			return c.scratch, errors.New("HTTP header block exceeds native guardian bound")
		}
		c.scratch = append(c.scratch, line...)
		lineBytes += len(line)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return c.scratch, err
		}
		if lineBytes <= 2 && (bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n"))) {
			return c.scratch, nil
		}
		lineBytes = 0
	}
	return c.scratch, errors.New("HTTP header block exceeds native guardian bound")
}

func (c *desyncConnection) readLine(limit int) ([]byte, error) {
	c.scratch = c.scratch[:0]
	for len(c.scratch) < limit {
		line, err := c.reader.ReadSlice('\n')
		if len(line) > limit-len(c.scratch) {
			return nil, errors.New("HTTP chunk line exceeds parser bound")
		}
		c.scratch = append(c.scratch, line...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return c.scratch, nil
	}
	return nil, errors.New("HTTP chunk line exceeds parser bound")
}

func (c *desyncConnection) failBody(err error) error {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	c.mu.Lock()
	c.bodyError = err
	c.mu.Unlock()
	// Stop all further reads, but leave writing available for the handler's 400.
	c.cancel()
	_ = c.Conn.SetReadDeadline(time.Now())
	return err
}

func (c *desyncConnection) rejectHeader(err error) error {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(c.Conn, "HTTP/1.1 400 Bad Request\r\nServer: awselb/2.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Request")
	// Half-close the response before draining unread input. A direct TCP
	// close with unread oversized/pipelined bytes can reset the connection
	// and discard the complete rejection response at the peer.
	_ = c.CloseWrite()
	_ = c.Conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buffer := c.scratch[:cap(c.scratch)]
	for {
		if _, readErr := c.reader.Read(buffer); readErr != nil {
			break
		}
	}
	_ = c.Close()
	return err
}
