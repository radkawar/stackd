package docker

import (
	"encoding/binary"
	"fmt"
	"io"
)

// CopyStream demultiplexes native non-TTY Engine stdout/stderr without retaining
// the full response. Callers own source attribution, line framing and limits.
func CopyStream(stdout, stderr io.Writer, src io.Reader) error {
	var buffer [32 << 10]byte
	return VisitStream(src, func(isStderr bool, frame io.Reader) error {
		dst := stdout
		if isStderr {
			dst = stderr
		}
		_, err := io.CopyBuffer(dst, frame, buffer[:])
		return err
	})
}

// VisitStream exposes each native non-TTY stdout/stderr frame without allocating
// its payload. The frame reader is valid only during visit; unread bytes are
// skipped. A truncated frame is an error, including when visit skips its body.
func VisitStream(src io.Reader, visit func(stderr bool, frame io.Reader) error) error {
	var header [8]byte
	frame := io.LimitedReader{R: src}
	for {
		if _, err := io.ReadFull(src, header[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if (header[0] != 1 && header[0] != 2) || header[1] != 0 || header[2] != 0 || header[3] != 0 {
			return fmt.Errorf("invalid Docker output stream")
		}
		frame.N = int64(binary.BigEndian.Uint32(header[4:]))
		if err := visit(header[0] == 2, &frame); err != nil {
			return err
		}
		if frame.N > 0 {
			if _, err := io.Copy(io.Discard, &frame); err != nil {
				return err
			}
		}
		if frame.N != 0 {
			return io.ErrUnexpectedEOF
		}
	}
}
