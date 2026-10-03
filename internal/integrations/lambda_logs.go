package integrations

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"stackd/clock"
	runtime "stackd/compute/lambda"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/lambda"
	"stackd/internal/services/logs"
)

// RuntimeLogsAPI is the same authorized command boundary used by public Logs
// requests. No invoker credentials or blanket service-principal bypass is used.
type RuntimeLogsAPI interface {
	CreateLogGroup(context.Context, *api.CreateLogGroupRequest) (*api.CreateLogGroupOutput, *awswire.Error)
	CreateLogStream(context.Context, *api.CreateLogStreamRequest) (*api.CreateLogStreamOutput, *awswire.Error)
	PutLogEvents(context.Context, *api.PutLogEventsRequest) (*api.PutLogEventsResponse, *awswire.Error)
}

// LambdaLogs connects real runtime bytes to retained CloudWatch Logs events.
// Customer code remains outside modeled time; timestamps are captured at this
// API edge. Logging errors are diagnosed without changing invocation outcomes.
// Runtime output is generation-scoped, not delimited by invocation. A preparation
// context must not become the causal parent of every later warm invocation.
// TODO: Comeback: correlate runtime output when its source supplies an invocation boundary.
type LambdaLogs struct {
	Logs        RuntimeLogsAPI
	Credentials interface {
		Resolve(context.Context, string) (identity.Credential, error)
	}
	Clock clock.Clock
}

func (a LambdaLogs) Open(_ context.Context, key lambda.FunctionKey, credentials runtime.Credentials, group, stream string) io.WriteCloser {
	return &runtimeLogWriter{provider: a, region: key.Region, accessKey: credentials.AccessKeyID, group: group, stream: stream}
}

type runtimeLogWriter struct {
	mu                               sync.Mutex
	provider                         LambdaLogs
	region, accessKey, group, stream string
	pending                          []byte
	ready                            bool
}

func (w *runtimeLogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	written := len(data)
	timestamp := w.provider.Clock.Now().UnixMilli()
	var events api.InputLogEvents
	for len(data) > 0 {
		n := len(data)
		if newline := bytes.IndexByte(data, '\n'); newline >= 0 {
			n = newline + 1
		}
		if available := logs.MaxBatchBytes - logs.EventOverheadBytes - len(w.pending); n > available {
			n = available
		}
		w.pending = append(w.pending, data[:n]...)
		data = data[n:]
		if w.pending[len(w.pending)-1] == '\n' || len(w.pending) == logs.MaxBatchBytes-logs.EventOverheadBytes {
			end := len(w.pending)
			// Preserve a valid multibyte character split by the event byte limit.
			start := end - 1
			for start > 0 && !utf8.RuneStart(w.pending[start]) {
				start--
			}
			if !utf8.FullRune(w.pending[start:]) {
				end = start
			}
			events = append(events, w.event(w.pending[:end], timestamp))
			copy(w.pending, w.pending[end:])
			w.pending = w.pending[:len(w.pending)-end]
		}
	}
	w.deliver(events)
	return written, nil
}

func (w *runtimeLogWriter) event(message []byte, timestamp int64) api.InputLogEvent {
	return api.InputLogEvent{Message: new(api.EventMessage(string(message))), Timestamp: new(api.Timestamp(timestamp))}
}

func (w *runtimeLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) != 0 {
		w.deliver(api.InputLogEvents{w.event(w.pending, w.provider.Clock.Now().UnixMilli())})
		w.pending = nil
	}
	return nil
}

func (w *runtimeLogWriter) deliver(events api.InputLogEvents) {
	if len(events) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	credential, err := w.provider.Credentials.Resolve(ctx, w.accessKey)
	if err != nil {
		w.failure("resolve execution role", err)
		return
	}
	metadata, err := identity.RequestMetadata(credential, w.accessKey, w.region, "")
	if err != nil {
		w.failure("resolve execution scope", err)
		return
	}
	metadata.SourceIP, metadata.UserAgent = "lambda.amazonaws.com", "lambda.amazonaws.com"
	command := func() context.Context {
		metadata.RequestID = uuid.NewString()
		return awsctx.WithMetadata(ctx, metadata)
	}
	group, stream := new(api.LogGroupName(w.group)), new(api.LogStreamName(w.stream))
	if !w.ready {
		// An execution role can lack CreateLogGroup while writing an existing
		// group. Each native command has its own independent authorization.
		if _, wire := w.provider.Logs.CreateLogGroup(command(), &api.CreateLogGroupRequest{LogGroupName: group}); wire != nil && wire.Code != "ResourceAlreadyExistsException" {
			w.failure("CreateLogGroup", wire)
		}
		if _, wire := w.provider.Logs.CreateLogStream(command(), &api.CreateLogStreamRequest{LogGroupName: group, LogStreamName: stream}); wire != nil && wire.Code != "ResourceAlreadyExistsException" {
			w.failure("CreateLogStream", wire)
			return
		}
		w.ready = true
	}
	for len(events) > 0 {
		count, size := 0, 0
		for count < len(events) && count < logs.MaxBatchEvents {
			additional := len(*events[count].Message) + logs.EventOverheadBytes
			if size+additional > logs.MaxBatchBytes {
				break
			}
			size += additional
			count++
		}
		_, wire := w.provider.Logs.PutLogEvents(command(), &api.PutLogEventsRequest{LogGroupName: group, LogStreamName: stream, LogEvents: events[:count]})
		if wire != nil {
			w.failure("PutLogEvents", wire)
			return
		}
		events = events[count:]
	}
}

func (w *runtimeLogWriter) failure(operation string, err error) {
	slog.Warn("Lambda log delivery failed", "operation", operation, "log_group", w.group, "log_stream", w.stream, "error", err)
}
