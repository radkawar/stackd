package lambda

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// The runtime's dedicated descriptor carries the published RIC framing protocol,
// not customer stdout/stderr. Never sniff frame signatures from ordinary output.
// References: aws-lambda-{python,nodejs}-runtime-interface-client log sinks.
type runtimeLogFrames struct {
	manager     *telemetryManager
	header      [16]byte
	headerBytes int
	remaining   uint32
	at          time.Time
	message     []byte
	severity    int
	fragmented  bool
}

func (s *runtimeLogFrames) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if s.headerBytes < len(s.header) {
			used := copy(s.header[s.headerBytes:], p)
			s.headerBytes += used
			p = p[used:]
			if s.headerBytes < len(s.header) {
				break
			}
			kind := binary.BigEndian.Uint32(s.header[:4])
			if kind&0xffff0000 != 0xa55a0000 {
				return n - len(p), fmt.Errorf("invalid runtime log frame type %x", kind)
			}
			s.remaining = binary.BigEndian.Uint32(s.header[4:8])
			s.at = time.UnixMicro(int64(binary.BigEndian.Uint64(s.header[8:16])))
			s.severity = int((kind & 0x1c) >> 2)
			if s.severity == 0 {
				s.severity = 3
			}
		}
		used := min(len(p), int(s.remaining), telemetryLineChunk-len(s.message))
		s.message = append(s.message, p[:used]...)
		p = p[used:]
		s.remaining -= uint32(used)
		if s.remaining == 0 || len(s.message) == telemetryLineChunk {
			s.emit(s.remaining == 0)
		}
		if s.remaining == 0 {
			s.headerBytes = 0
		}
	}
	return n, nil
}

func (s *runtimeLogFrames) emit(final bool) {
	if len(s.message) == 0 {
		return
	}
	body, _ := json.Marshal(string(s.message))
	s.manager.emitRecord(s.at, "function", body)
	if final && s.message[len(s.message)-1] != '\n' {
		s.message = append(s.message, '\n')
	}
	// A frame larger than the bounded framer has already evicted the JSON
	// tail. Its remaining fragments must not become independently eligible
	// records or suppress another pipe's complete records.
	capture := s.manager.logging.Format != "JSON" || !s.fragmented
	s.manager.forward(s.message, s.manager.logging.Format != "JSON" || s.severity >= logSeverity(s.manager.logging.ApplicationLevel), capture)
	s.fragmented = !final
	s.message = s.message[:0]
}

func (s *runtimeLogFrames) Close() error {
	if s.headerBytes != 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (e *dockerEnvironment) customerLoggingCommand(ctx context.Context, name, kind string, command []string) ([]string, error) {
	path := "/tmp/." + e.identity + "-" + newRuntimeID() + ".logs"
	logging, err := json.Marshal(e.spec.Logging)
	if err != nil {
		return nil, err
	}
	if _, err := e.telemetry.remote.call(ctx, telemetryCommand{Operation: "open-output", Path: path, Name: name, Kind: kind, Body: logging}); err != nil {
		return nil, fmt.Errorf("opening customer output: %w", err)
	}
	return append([]string{"/bin/bash", "-c", `exec >"$1.stdout" 2>"$1.stderr"
if test "$2" = function; then exec 3>"$1.frames"; export _LAMBDA_TELEMETRY_LOG_FD=3; fi
shift 2
exec "$@"`, "stackd-runtime-logs", path, kind}, command...), nil
}

func (e *dockerEnvironment) drainOutput(ctx context.Context) error {
	_, err := e.telemetry.remote.call(ctx, telemetryCommand{Operation: "drain-output"})
	return err
}
