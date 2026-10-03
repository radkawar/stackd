package lambda

import (
	"context"
	"errors"
	"time"

	"stackd/compute/lambda/internal/telemetryapi"
)

func (e *dockerEnvironment) initializationType() telemetryapi.InitType {
	if e.spec.Provisioned {
		return "provisioned-concurrency"
	}
	return "on-demand"
}

// preinitialize runs the ordinary customer Init phase without fabricating an
// invocation. Runtime and extension Next barriers prove actual initialization.
func (e *dockerEnvironment) preinitialize(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.done:
		return e.failure()
	case <-e.gate:
	}
	defer func() { e.gate <- struct{}{} }()
	e.initAttempted = true
	started := time.Now()
	// AWS grants provisioned Init at least 130 seconds, or the function timeout.
	timeout := max(130*time.Second, e.spec.Timeout)
	initCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	e.telemetry.Emit(started, "platform.initStart", telemetryapi.PlatformInitStart{InitializationType: e.initializationType(), Phase: "init", FunctionName: &e.spec.FunctionName, FunctionVersion: new(e.functionVersion())})
	runtime, err := e.startRuntime(initCtx, "init")
	if err == nil {
		err = runtime.waitReady(initCtx)
	}
	status, errorType := "success", ""
	if err != nil {
		status = "error"
		var customer *customerFailure
		if errors.As(err, &customer) {
			errorType = customer.errorType
		}
		if errors.Is(err, context.DeadlineExceeded) {
			status, errorType = "timeout", "Sandbox.Timedout"
		}
	}
	report := telemetryapi.PlatformInitReport{InitializationType: e.initializationType(), Phase: "init", Status: &status, Metrics: telemetryapi.InitReportMetrics{DurationMs: float64(time.Since(started)) / float64(time.Millisecond)}}
	if errorType != "" {
		report.ErrorType = &errorType
	}
	e.telemetry.Emit(time.Now(), "platform.initReport", report)
	if err != nil {
		return err
	}
	if err := e.drainOutput(initCtx); err != nil {
		return err
	}
	return e.setFrozen(initCtx, true)
}
