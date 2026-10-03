// Package glue runs real AWS-targeted job processes through the shared Docker transport.
package glue

import "context"

// Runtime never owns Glue state or credentials. A retained key names one execution;
// Inspect never starts or restarts customer code, including after controller loss.
// Inspect errors mean authoritative state/ownership could not be established.
// Optional output/metrics failures are returned in Status.ObservationError.
type Runtime interface {
	SetCredentials(context.Context, string, CredentialProvider) error
	Start(context.Context, Execution) error
	Inspect(context.Context, string) (Status, error)
	Stop(context.Context, string) error
	Remove(context.Context, string) error
}

type Execution struct {
	Key, Command, Region          string
	Script                        []byte
	Arguments                     map[string]string
	Environment                   []string
	S3EncryptionMode, S3KMSKeyARN string
}

type Status struct {
	Found, Running             bool
	ExitCode                   int
	ExecutionSeconds           int32
	Error, Output, ErrorOutput string
	SparkMetrics               SparkMetrics
	// ObservationError does not change the native process outcome. The service
	// retains it with its existing log diagnostics, independently of cleanup.
	ObservationError string
}
