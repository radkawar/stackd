package lambda

import (
	"encoding/json"
	"strings"
	"time"
)

func logSeverity(level string) int {
	switch strings.ToUpper(level) {
	case "TRACE":
		return 1
	case "DEBUG":
		return 2
	case "WARN", "WARNING":
		return 4
	case "ERROR":
		return 5
	case "FATAL", "CRITICAL":
		return 6
	default:
		return 3
	}
}

// Unframed customer stdout is not a runtime logging method. Preserve its bytes.
// Native captures filter a valid level even when timestamp is absent, contrary
// to the documented timestamp fallback. Missing/invalid levels are INFO.
func (m *telemetryManager) acceptsApplication(line []byte) bool {
	if m.logging.Format != "JSON" {
		return true
	}
	var record struct {
		Level string `json:"level"`
	}
	level := 3
	if json.Unmarshal(line, &record) == nil {
		level = logSeverity(record.Level)
	}
	return level >= logSeverity(m.logging.ApplicationLevel)
}

func (m *telemetryManager) renderPlatformJSON(at time.Time, kind string, body json.RawMessage) {
	// END belongs to the legacy Logs API, not the JSON system event vocabulary.
	if kind == "platform.end" || kind == "platform.fault" {
		return
	}
	var fields struct {
		Status             string `json:"status"`
		State              string `json:"state"`
		RuntimeVersion     string `json:"runtimeVersion"`
		InitializationType string `json:"initializationType"`
	}
	if json.Unmarshal(body, &fields) != nil {
		return
	}
	level := 3
	switch kind {
	case "platform.initStart", "platform.restoreStart":
		if fields.RuntimeVersion == "" {
			level = 2
		}
	case "platform.initRuntimeDone", "platform.restoreRuntimeDone", "platform.runtimeDone":
		level = 2
		if fields.Status != "success" {
			level = 4
		}
	case "platform.initReport":
		if fields.InitializationType == "on-demand" {
			level = 2
		}
		if fields.Status != "" && fields.Status != "success" {
			level = 4
		}
	case "platform.report", "platform.restoreReport":
		if fields.Status != "" && fields.Status != "success" {
			level = 4
		}
	case "platform.extension":
		if fields.State != "Ready" && fields.State != "success" {
			level = 4
		}
	case "platform.logsDropped":
		level = 4
	}
	line, err := json.Marshal(struct {
		Time   string          `json:"time"`
		Type   string          `json:"type"`
		Record json.RawMessage `json:"record"`
	}{at.UTC().Format(time.RFC3339Nano), kind, body})
	if err == nil {
		m.forward(append(line, '\n'), level >= logSeverity(m.logging.SystemLevel), true)
	}
}
