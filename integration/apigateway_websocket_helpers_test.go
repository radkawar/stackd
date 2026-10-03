package stackd_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// gatewayWSConn keeps the dialer's buffered bytes: an eager management callback
// may already have sent a frame in the same packet as the upgrade response.
// Close is physical cleanup; a fixture's peer-close is sent explicitly with Send.
type gatewayWSConn struct {
	conn   net.Conn
	buffer *bufio.Reader
	reader io.Reader
}

func gatewayWSDial(ctx context.Context, url string, headers http.Header) (*gatewayWSConn, int, http.Header, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var status int
	var body []byte
	var responseHeaders http.Header
	var responseErr error
	dialer := ws.Dialer{
		Timeout: 15 * time.Second,
		Header:  ws.HandshakeHeaderHTTP(headers),
		OnStatusError: func(code int, _ []byte, source io.Reader) {
			status = code
			response, err := http.ReadResponse(bufio.NewReader(source), nil)
			if err != nil {
				responseErr = err
				return
			}
			defer response.Body.Close()
			responseHeaders = response.Header
			body, responseErr = io.ReadAll(response.Body)
		},
	}
	conn, buffered, _, err := dialer.Dial(ctx, url)
	if err != nil {
		return nil, status, responseHeaders, body, errors.Join(err, responseErr)
	}
	reader := io.Reader(conn)
	if buffered != nil {
		reader = buffered
	}
	return &gatewayWSConn{conn: conn, buffer: buffered, reader: reader}, http.StatusSwitchingProtocols, nil, nil, nil
}

func (c *gatewayWSConn) Send(opcode ws.OpCode, payload []byte) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return wsutil.WriteClientMessage(c.conn, opcode, payload)
}

func (c *gatewayWSConn) Read(timeout time.Duration) ([]byte, ws.OpCode, error) {
	if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, 0, err
	}
	var closePayload []byte
	closed := errors.New("websocket close within fragmented message")
	handleControl := func(opcode ws.OpCode, payload []byte) error {
		switch opcode {
		case ws.OpPing:
			return c.Send(ws.OpPong, payload)
		case ws.OpClose:
			closePayload = payload
			// The observed close is the evidence even if its acknowledgement
			// races the peer's physical socket shutdown.
			_ = c.Send(ws.OpClose, payload)
			return closed
		}
		return nil
	}
	reader := wsutil.Reader{
		Source:    c.reader,
		State:     ws.StateClientSide,
		CheckUTF8: true,
		OnIntermediate: func(header ws.Header, source io.Reader) error {
			payload, err := io.ReadAll(source)
			if err != nil {
				return err
			}
			return handleControl(header.OpCode, payload)
		},
	}
	for {
		header, err := reader.NextFrame()
		if err != nil {
			return nil, 0, err
		}
		payload, err := io.ReadAll(&reader)
		if errors.Is(err, closed) {
			return closePayload, ws.OpClose, nil
		}
		if err != nil {
			return payload, header.OpCode, err
		}
		if !header.OpCode.IsControl() {
			return payload, header.OpCode, nil
		}
		if err := handleControl(header.OpCode, payload); errors.Is(err, closed) {
			return closePayload, ws.OpClose, nil
		} else if err != nil {
			return nil, header.OpCode, err
		}
	}
}

func (c *gatewayWSConn) Close() error {
	err := c.conn.Close()
	if c.buffer != nil {
		ws.PutReader(c.buffer)
		c.buffer = nil
	}
	return err
}
