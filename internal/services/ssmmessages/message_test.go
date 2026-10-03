package ssmmessages

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRejectMalformedAgentFrames(t *testing.T) {
	m := Message{ID: uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff"), Type: "agent_job_reply", CreatedAt: time.UnixMilli(1700000000000), Payload: []byte(`{"jobId":"job","schemaVersion":1}`)}
	encoded, err := encodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"short-header", func(b []byte) []byte { return b[:119] }},
		{"short-payload", func(b []byte) []byte { return b[:len(b)-1] }},
		{"trailing-payload", func(b []byte) []byte { return append(b, 0) }},
		{"header-overflow", func(b []byte) []byte { binary.BigEndian.PutUint32(b[:4], ^uint32(0)); return b }},
		{"wrong-schema", func(b []byte) []byte { binary.BigEndian.PutUint32(b[36:40], 2); return b }},
		{"stream-payload", func(b []byte) []byte { binary.BigEndian.PutUint32(b[112:116], 1); return b }},
		{"digest-corruption", func(b []byte) []byte { b[80] ^= 1; return b }},
		{"payload-corruption", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }},
		{"empty-uuid", func(b []byte) []byte { clear(b[64:80]); return b }},
		{"invalid-type", func(b []byte) []byte { b[4] = 0; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeMessage(tc.change(append([]byte(nil), encoded...))); err == nil {
				t.Fatal("accepted malformed frame")
			}
		})
	}
}
