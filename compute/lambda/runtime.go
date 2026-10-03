// Package lambda defines the execution boundary consumed by Lambda's control plane.
// Implementations run real runtimes; no in-process handler execution is supported.
package lambda

import (
	"context"
	"io"
	"time"
)

// Executor allocates a real execution environment and verifies its backend
// prerequisites. Customer runtime and extension initialization belongs to Invoke,
// not deployment readiness: customer initialization errors do not fail deployment.
// A non-nil Environment returned with an error still owns resources whose cleanup
// failed; the caller must retry Close. Successful cleanup returns nil on failure.
type Executor interface {
	Prepare(context.Context, Specification) (Environment, error)
}

// Specification is an immutable deployment and execution-role snapshot. Code
// and Layers contain original ZIP archives; Layers retain merge order at /opt.
// Endpoint is the reachable stackd AWS API origin.
type Specification struct {
	FunctionARN, FunctionName, Runtime, Handler, Architecture string
	Code                                                      []byte
	Layers                                                    [][]byte
	Variables                                                 map[string]string
	Timeout                                                   time.Duration
	MemoryMB, EphemeralMB                                     int
	Credentials                                               Credentials
	Endpoint                                                  string
	// Provisioned starts customer Init and waits for the Runtime API and all
	// extensions before Prepare succeeds, without sending a handler invocation.
	Provisioned bool
	// LogGroup and LogStream identify the caller-owned log destination exposed
	// to customer runtimes. Empty values retain the executor's local defaults.
	LogGroup, LogStream string
	Logging             LoggingConfig
	// Logs receives application output and rendered platform events after the
	// deployment's CloudWatch filtering. Telemetry subscriptions are independent.
	// Writes are serialized and may split lines. The writer must return promptly;
	// failures are diagnosed separately from customer execution. The caller owns
	// the writer until Close completes. Nil disables forwarding.
	Logs io.Writer
}

// LoggingConfig is an immutable deployment control. The zero value means Text
// with no level filtering. JSON deployments have explicit application/system
// levels; the control plane supplies their INFO defaults.
type LoggingConfig struct {
	Format, ApplicationLevel, SystemLevel string
}

// Credentials are expiring local role credentials, never the deployer's keys.
type Credentials struct {
	AccessKeyID, SecretAccessKey, SessionToken string
	Expiration                                 time.Time
}

// Environment owns one execution environment, including warm reuse and cleanup.
// Invoke calls respond once when a function response is available, then waits for
// the runtime and every participating extension to finish the invocation phase.
// respond must return promptly. Its result remains final even if later extension
// work fails. Runtime failures and timeouts produce a function error response when
// none was sent, and a failed Report; they reset processes while retaining /tmp.
// Returned errors denote backend failure or cancellation, which must stop owned
// customer processes. Close also owns extension shutdown and resource cleanup.
type Environment interface {
	Invoke(context.Context, Invocation, func(Result)) (Report, error)
	Close(context.Context) error
}

// Invocation carries trusted API identity and the customer's unmodified payload.
type Invocation struct {
	RequestID string
	// FunctionARN includes the version or alias used by this invocation.
	FunctionARN   string
	Payload       []byte
	ClientContext string
	TraceID       string
	// Stream receives response bytes when the runtime uses streaming mode.
	// The slice is borrowed until Stream returns. Calls are serialized and finish
	// before respond or Invoke returns. The context ends at the invocation deadline.
	// Delivery cancellation must discard bytes, not cancel customer execution.
	// Nil retains the synchronous buffered response contract.
	Stream func(context.Context, string, []byte) error
}

// Result is the function response. Function errors remain successful Invoke API
// responses with an error payload and header, independent of later phase failure.
type Result struct {
	Payload       []byte
	FunctionError string
	ContentType   string
	Streaming     bool
	// ExtensionsPending distinguishes an early response from an execution whose
	// lease must be released before exposing the response to the next caller.
	ExtensionsPending bool
}

// InvocationStatus describes the completed runtime-and-extension phase.
type InvocationStatus string

const (
	InvocationSuccess InvocationStatus = "success"
	InvocationFailure InvocationStatus = "error"
	InvocationTimeout InvocationStatus = "timeout"
)

// Report contains completed-phase measurements, not the early function result.
// Durations measure real execution time; the service clock owns publication time.
type Report struct {
	Status                        InvocationStatus
	Duration                      time.Duration
	PostRuntimeExtensionsDuration time.Duration
	// FunctionFailed counts reported handler errors and oversized responses.
	// Streaming APIs can omit FunctionError even when this is true; phase
	// status and asynchronous destination routing remain separate.
	FunctionFailed bool
	// HasExtensions preserves an observed zero duration versus no extension metric.
	HasExtensions bool
	Logs          []byte
}
