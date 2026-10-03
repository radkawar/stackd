package lambda

import (
	"context"
	"io"
	"time"

	"stackd/compute/lambda/internal/telemetryapi"
)

// ManagedLogRenderer shares the ordinary Lambda application filtering and
// platform event formatting without imposing its single-invocation tail state.
// A concurrent environment owns output attribution and capture separately.
type ManagedLogRenderer struct{ manager *telemetryManager }

func NewManagedLogRenderer(ctx context.Context, config LoggingConfig, output io.Writer) *ManagedLogRenderer {
	manager := newTelemetryManager(ctx, nil, output)
	manager.logging = config
	return &ManagedLogRenderer{manager: manager}
}
func (l *ManagedLogRenderer) Application() io.Writer { return l.manager.Output("function", "") }
func (l *ManagedLogRenderer) Start(requestID, version string) {
	l.manager.Emit(time.Now(), "platform.start", telemetryapi.PlatformStart{RequestId: requestID, Version: &version})
}
func (l *ManagedLogRenderer) Finish(requestID string, report Report, memoryMB int) {
	at := time.Now()
	l.manager.Emit(at, "platform.end", telemetryapi.LogsPlatformEnd{RequestId: requestID})
	status := string(report.Status)
	memory := uint64(memoryMB)
	l.manager.Emit(at, "platform.report", telemetryapi.PlatformReport{RequestId: requestID, Status: &status, Metrics: telemetryapi.ReportMetrics{DurationMs: float64(report.Duration) / float64(time.Millisecond), MemorySizeMB: &memory}})
}
func (l *ManagedLogRenderer) Close() error { return l.manager.Close() }
