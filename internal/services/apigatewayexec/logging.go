package apigatewayexec

import (
	"context"
	"time"
)

// AccessLogSettings is stage-owned configuration, independent of a deployment.
type AccessLogSettings struct {
	DestinationARN string
	Format         string
}

// LoggingSettings contains the effective settings selected for an execution.
// Only REST and WebSocket APIs have execution logs.
type LoggingSettings struct {
	Access    AccessLogSettings
	Level     string
	DataTrace bool
}

// LoggingConfiguration admits delivery through the current Logs and IAM owners.
// Implementations join the caller's transaction and perform no external IO.
type LoggingConfiguration interface {
	ConfigureAccessLogs(context.Context, string, AccessLogSettings) error
	RequireLoggingRole(context.Context) error
}

// LogPublisher delivers observations after execution, outside configuration
// transactions. Delivery failures must not change the client response.
type LogPublisher interface {
	PublishLogs(context.Context, *Route, time.Time, string, []string) error
}
