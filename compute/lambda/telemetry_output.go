package lambda

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"stackd/compute/lambda/internal/telemetryapi"
)

// Each process pipe has its own framer, including separate stdout/stderr pipes.
// Origin is supplied by process ownership, never inferred from customer text.
// Long unterminated lines are chunked, not truncated; forwarding is byte-exact.
const telemetryLineChunk = 256 << 10

type telemetryOutput struct {
	manager    *telemetryManager
	kind, name string
	mu         sync.Mutex
	line       []byte
	at         time.Time
	closed     bool
}

func (m *telemetryManager) Output(kind, name string) io.Writer {
	stream := &telemetryOutput{manager: m, kind: kind, name: name}
	m.mu.Lock()
	if m.closed {
		stream.closed = true
	} else {
		m.streams[stream] = struct{}{}
	}
	m.mu.Unlock()
	return stream
}

func (s *telemetryOutput) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	n := len(p)
	if len(s.line) == 0 {
		s.at = time.Now()
	}
	s.line = append(s.line, p...)
	consumed := 0
	for consumed < len(s.line) {
		remaining := s.line[consumed:]
		size := min(len(remaining), telemetryLineChunk)
		if newline := bytes.IndexByte(remaining[:size], '\n'); newline >= 0 {
			size = newline + 1
		} else if size < telemetryLineChunk {
			break
		}
		s.emit(remaining[:size])
		s.manager.forward(remaining[:size], s.kind != "function" || s.manager.acceptsApplication(remaining[:size]), true)
		consumed += size
		s.at = time.Now()
	}
	copy(s.line, s.line[consumed:])
	s.line = s.line[:len(s.line)-consumed]
	return n, nil
}

func (s *telemetryOutput) emit(line []byte) {
	body, err := json.Marshal(string(line))
	if err != nil {
		slog.Error("Lambda output encoding failed", "source", s.kind, "name", s.name, "error", err)
	} else {
		s.manager.emitRecord(s.at, s.kind, body)
	}
}

func (s *telemetryOutput) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if len(s.line) > 0 {
		s.emit(s.line)
		// Closing flushes unfinished output to subscribers and CloudWatch, not
		// to whichever invocation happens to be active during runtime reset.
		s.manager.forward(s.line, s.kind != "function" || s.manager.acceptsApplication(s.line), false)
		s.line = nil
	}
	s.closed = true
	s.manager.mu.Lock()
	delete(s.manager.streams, s)
	s.manager.mu.Unlock()
	s.manager.flush()
	return nil
}

func (m *telemetryManager) forward(p []byte, deliver, capture bool) {
	if len(p) == 0 {
		return
	}
	if m.forwardOutput != nil {
		m.forwardOutput(p, deliver, capture)
		return
	}
	m.outputMu.Lock()
	defer m.outputMu.Unlock()
	if m.tailActive && capture {
		m.captureTail(p)
	}
	if deliver && m.output != nil {
		n, err := m.output.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		if err != nil && !m.sinkFailed {
			slog.Warn("Lambda log delivery failed", "error", err)
			m.sinkFailed = true
		}
	}
}

func (m *telemetryManager) BeginInvocation() {
	m.outputMu.Lock()
	m.tail = m.tail[:0]
	m.tailRecords = m.tailRecords[:0]
	m.tailActive = true
	m.outputMu.Unlock()
}

// EndInvocation seals only the caller's tail. Full log delivery and subscribers
// continue independently, including output produced while no invocation owns it.
func (m *telemetryManager) EndInvocation() []byte {
	m.outputMu.Lock()
	defer m.outputMu.Unlock()
	m.tailActive = false
	if !utf8.Valid(m.tail) {
		// Native Text truncates bytes first, then replaces each invalid byte,
		// so the decoded UTF-8 result can exceed 4096 bytes.
		return bytes.Map(func(r rune) rune { return r }, m.tail)
	}
	return bytes.Clone(m.tail)
}

func (m *telemetryManager) captureTail(p []byte) {
	const limit = 4096
	if m.logging.Format == "JSON" {
		// JSON keeps complete records, including unstructured stdout records.
		// An oversized record evicts older records but is not returned partially.
		if len(p) > limit {
			m.tail = m.tail[:0]
			m.tailRecords = m.tailRecords[:0]
		} else {
			for len(m.tail)+len(p) > limit && len(m.tailRecords) != 0 {
				size := m.tailRecords[0]
				copy(m.tail, m.tail[size:])
				m.tail = m.tail[:len(m.tail)-size]
				copy(m.tailRecords, m.tailRecords[1:])
				m.tailRecords = m.tailRecords[:len(m.tailRecords)-1]
			}
			m.tail = append(m.tail, p...)
			m.tailRecords = append(m.tailRecords, len(p))
		}
		return
	}
	if len(p) >= limit {
		m.tail = append(m.tail[:0], p[len(p)-limit:]...)
		return
	}
	if excess := len(m.tail) + len(p) - limit; excess > 0 {
		copy(m.tail, m.tail[excess:])
		m.tail = m.tail[:len(m.tail)-excess]
	}
	m.tail = append(m.tail, p...)
}

func (m *telemetryManager) subscriptionEvent(name, api, state string, types []telemetryapi.EventType) {
	at := time.Now()
	if api == "Logs" {
		names := make([]string, len(types))
		for i, kind := range types {
			names[i] = string(kind)
		}
		m.Emit(at, "platform.logsSubscription", telemetryapi.LogsPlatformLogsSubscription{Name: name, State: state, Types: names})
	} else {
		names := make([]telemetryapi.SubscriptionEventType, len(types))
		for i, kind := range types {
			names[i] = telemetryapi.SubscriptionEventType(kind)
		}
		m.Emit(at, "platform.telemetrySubscription", telemetryapi.PlatformTelemetrySubscription{Name: name, State: state, Types: names})
	}
}

func projectTelemetryRecord(version telemetryapi.SchemaVersion, eventType string, body json.RawMessage) (json.RawMessage, error) {
	if telemetryapi.Versions[version].API == "Logs" && eventType == "platform.runtimeDone" {
		var record telemetryapi.PlatformRuntimeDone
		if err := json.Unmarshal(body, &record); err != nil {
			return nil, err
		}
		return json.Marshal(telemetryapi.LogsPlatformRuntimeDone{RequestId: record.RequestId, Status: telemetryapi.LogsRuntimeDoneStatus(record.Status)})
	}
	omitted := telemetryapi.Versions[version].OmitFields[eventType]
	if len(omitted) == 0 {
		return body, nil
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, err
	}
	for _, path := range omitted {
		if err := omitTelemetryField(record, strings.Split(path, ".")); err != nil {
			return nil, err
		}
	}
	return json.Marshal(record)
}

func omitTelemetryField(record map[string]json.RawMessage, path []string) error {
	if len(path) == 1 {
		delete(record, path[0])
		return nil
	}
	value, exists := record[path[0]]
	if !exists || bytes.Equal(value, []byte("null")) {
		return nil
	}
	var child map[string]json.RawMessage
	if err := json.Unmarshal(value, &child); err != nil {
		return err
	}
	if err := omitTelemetryField(child, path[1:]); err != nil {
		return err
	}
	value, err := json.Marshal(child)
	if err != nil {
		return err
	}
	record[path[0]] = value
	return nil
}

func (m *telemetryManager) renderPlatform(at time.Time, kind string, body json.RawMessage) {
	if m.logging.Format == "JSON" {
		m.renderPlatformJSON(at, kind, body)
		return
	}
	var line string
	switch kind {
	case "platform.start":
		var r telemetryapi.PlatformStart
		if !decodePlatformText(kind, body, &r) {
			return
		}
		line = "START RequestId: " + r.RequestId
		if r.Version != nil {
			line += " Version: " + *r.Version
		}
	case "platform.end":
		var r telemetryapi.LogsPlatformEnd
		if !decodePlatformText(kind, body, &r) {
			return
		}
		line = "END RequestId: " + r.RequestId
	case "platform.report":
		var r telemetryapi.PlatformReport
		if !decodePlatformText(kind, body, &r) {
			return
		}
		line = fmt.Sprintf("REPORT RequestId: %s\tDuration: %.2f ms", r.RequestId, r.Metrics.DurationMs)
		if r.Metrics.BilledDurationMs != nil {
			line += fmt.Sprintf("\tBilled Duration: %d ms", *r.Metrics.BilledDurationMs)
		}
		if r.Metrics.MemorySizeMB != nil {
			line += fmt.Sprintf("\tMemory Size: %d MB", *r.Metrics.MemorySizeMB)
		}
		if r.Metrics.MaxMemoryUsedMB != nil {
			line += fmt.Sprintf("\tMax Memory Used: %d MB", *r.Metrics.MaxMemoryUsedMB)
		}
		if r.Metrics.InitDurationMs != nil {
			line += fmt.Sprintf("\tInit Duration: %.2f ms", *r.Metrics.InitDurationMs)
		}
		if r.Metrics.RestoreDurationMs != nil {
			line += fmt.Sprintf("\tRestore Duration: %.2f ms", *r.Metrics.RestoreDurationMs)
		}
		line += telemetryStatusText(r.Status, r.ErrorType)
		if telemetryStatusText(r.Status, r.ErrorType) == "" {
			line += "\t"
		}
	case "platform.initStart":
		var r telemetryapi.PlatformInitStart
		if !decodePlatformText(kind, body, &r) {
			return
		}
		// Runtime version identifiers are AWS-supplied metadata, not the image
		// name. Do not manufacture them for Docker-backed environments.
		if r.RuntimeVersion == nil && r.RuntimeVersionArn == nil {
			return
		}
		line = "INIT_START"
		if r.RuntimeVersion != nil {
			line += " Runtime Version: " + *r.RuntimeVersion
		}
		if r.RuntimeVersionArn != nil {
			line += "\tRuntime Version ARN: " + *r.RuntimeVersionArn
		}
	case "platform.initReport":
		var r telemetryapi.PlatformInitReport
		if !decodePlatformText(kind, body, &r) {
			return
		}
		if r.InitializationType == "on-demand" && (r.Status == nil || *r.Status == "success") {
			return
		}
		line = fmt.Sprintf("INIT_REPORT Init Duration: %.2f ms\tPhase: %s", r.Metrics.DurationMs, r.Phase)
		line += telemetryStatusText(r.Status, r.ErrorType)
	case "platform.restoreStart":
		line = "RESTORE_START"
	case "platform.restoreReport":
		var r telemetryapi.PlatformRestoreReport
		if !decodePlatformText(kind, body, &r) {
			return
		}
		line = fmt.Sprintf("RESTORE_REPORT Restore Duration: %.2f ms", r.Metrics.DurationMs)
		line += telemetryStatusText(r.Status, r.ErrorType)
	case "platform.extension":
		var r telemetryapi.PlatformExtension
		if !decodePlatformText(kind, body, &r) {
			return
		}
		line = fmt.Sprintf("EXTENSION\tName: %s\tState: %s\tEvents: %v", r.Name, r.State, r.Events)
		if r.ErrorType != nil {
			line += "\tError Type: " + *r.ErrorType
		}
	case "platform.logsSubscription", "platform.telemetrySubscription":
		var r telemetryapi.LogsPlatformLogsSubscription
		if !decodePlatformText(kind, body, &r) {
			return
		}
		label := "LOGS"
		if kind == "platform.telemetrySubscription" {
			label = "TELEMETRY"
		}
		line = fmt.Sprintf("%s\tName: %s\tState: %s\tTypes: %v", label, r.Name, r.State, r.Types)
	default:
		return // Structured-only events have no additional platform text line.
	}
	m.forward([]byte(line+"\n"), true, true)
}

func telemetryStatusText(status, errorType *string) string {
	var text string
	if status != nil && *status != "success" {
		text = "\tStatus: " + *status
	}
	if errorType != nil {
		text += "\tError Type: " + *errorType
	}
	return text
}

func decodePlatformText(kind string, body []byte, destination any) bool {
	if err := json.Unmarshal(body, destination); err != nil {
		slog.Error("Lambda platform text rendering failed", "type", kind, "error", err)
		return false
	}
	return true
}
