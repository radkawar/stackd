// Package ssmmessages implements the official SSM agent's MGS control channel.
// Wire definitions follow amazon-ssm-agent c8fa314de8050cd5dcb3740a29c3ce769f533dcd,
// agent/session/{contracts,service,communicator,controlchannel}. Run Command state
// and retransmission timing belong to Backend, not this transport.
package ssmmessages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Message carries one native agent envelope. Payload is the official JSON body.
// Backend must retain a stable ID and CreatedAt when redelivering a job.
type Message struct {
	ID        uuid.UUID
	Type      string
	CreatedAt time.Time
	Payload   []byte
}

// Backend owns node admission, current IAM/credential authority and durable jobs.
// AuthorizeAgent must resolve current credentials, not just the connection's
// authenticated identity snapshot. ReceiveMessage must commit before returning.
// The context contains gateway-authenticated awsctx metadata. Calls for one node
// are fenced against a replacement connection, including in-flight deliveries.
type Backend interface {
	AuthorizeAgent(ctx context.Context, nodeID, action string) error
	PendingMessages(ctx context.Context, nodeID string) ([]Message, error)
	ReceiveMessage(ctx context.Context, nodeID string, message Message) error
}

const (
	headerLength   = 116 // excludes the four-byte payload length, as upstream does
	payloadOffset  = headerLength + 4
	maxMessageSize = 1 << 20
)

func encodeMessage(m Message) ([]byte, error) {
	if m.ID == uuid.Nil || !validMessageType(m.Type) || m.CreatedAt.UnixMilli() < 0 || len(m.Payload) > maxMessageSize-payloadOffset {
		return nil, errors.New("invalid agent message envelope")
	}
	b := make([]byte, payloadOffset+len(m.Payload))
	binary.BigEndian.PutUint32(b[0:4], headerLength)
	for i := 4; i < 36; i++ {
		b[i] = ' '
	}
	copy(b[4:36], m.Type)
	binary.BigEndian.PutUint32(b[36:40], 1)
	binary.BigEndian.PutUint64(b[40:48], uint64(m.CreatedAt.UnixMilli()))
	// Sequence, flags and payload type are zero for control-channel jobs.
	copy(b[64:72], m.ID[8:16])
	copy(b[72:80], m.ID[0:8])
	digest := sha256.Sum256(m.Payload)
	copy(b[80:112], digest[:])
	binary.BigEndian.PutUint32(b[116:120], uint32(len(m.Payload)))
	copy(b[payloadOffset:], m.Payload)
	return b, nil
}

func decodeMessage(b []byte) (Message, error) {
	var m Message
	if len(b) < payloadOffset || len(b) > maxMessageSize || binary.BigEndian.Uint32(b[:4]) != headerLength {
		return m, errors.New("invalid agent message header length")
	}
	if binary.BigEndian.Uint32(b[36:40]) != 1 || binary.BigEndian.Uint32(b[112:116]) != 0 || binary.BigEndian.Uint64(b[48:56]) != 0 || binary.BigEndian.Uint64(b[56:64]) != 0 {
		return m, errors.New("unsupported agent control message schema")
	}
	if uint64(binary.BigEndian.Uint32(b[116:120])) != uint64(len(b)-payloadOffset) {
		return m, errors.New("invalid agent message payload length")
	}
	created := binary.BigEndian.Uint64(b[40:48])
	if created > math.MaxInt64 {
		return m, errors.New("invalid agent message timestamp")
	}
	m.Type = strings.TrimRight(string(b[4:36]), " ")
	if !validMessageType(m.Type) {
		return m, errors.New("invalid agent message type")
	}
	copy(m.ID[8:16], b[64:72])
	copy(m.ID[0:8], b[72:80])
	if m.ID == uuid.Nil {
		return m, errors.New("invalid agent message ID")
	}
	m.CreatedAt = time.UnixMilli(int64(created)).UTC()
	m.Payload = b[payloadOffset:]
	digest := sha256.Sum256(m.Payload)
	if !bytes.Equal(b[80:112], digest[:]) {
		return Message{}, errors.New("invalid agent message payload digest")
	}
	return m, nil
}

func validMessageType(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
