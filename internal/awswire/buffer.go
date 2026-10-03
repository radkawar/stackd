package awswire

import (
	"bytes"
	"net/http"
)

// Buffer serializes a response while service state is locked, then sends the
// immutable result after unlocking. It deliberately does not stream or flush.
type Buffer struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func NewBuffer() *Buffer { return &Buffer{header: make(http.Header)} }

func (b *Buffer) Header() http.Header { return b.header }

func (b *Buffer) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *Buffer) Write(data []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(data)
}

// Send writes the buffered response once state is no longer being accessed.
func (b *Buffer) Send(w http.ResponseWriter) {
	for key, values := range b.header {
		w.Header()[key] = append([]string(nil), values...)
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body.Bytes())
}
