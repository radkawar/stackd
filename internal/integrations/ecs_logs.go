package integrations

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"stackd/clock"
	runtime "stackd/compute/ecs"
	ecsapi "stackd/internal/awsapi/ecs"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
	"stackd/internal/services/ecs"
	"stackd/internal/services/logs"
)

// ECSLogs delivers observed task output through the ordinary authorized Logs
// commands. It owns no credentials, AWS resource state, or durable log cursor.
type ECSLogs struct {
	Logs  RuntimeLogsAPI
	Clock clock.Clock
}

// The native Moby awslogs driver still splits at 256 KiB minus event overhead,
// independently of the CloudWatch Logs API's larger maximum event size.
const ecsLogEventBytes = 262144 - logs.EventOverheadBytes

var _ ecs.TaskLogs = ECSLogs{}

func (a ECSLogs) Open(ctx context.Context, key ecs.TaskKey, container string, config ecsapi.LogConfiguration, credentials ecs.TaskCredentialSource) (ecs.TaskLogSink, error) {
	if config.LogDriver == nil || *config.LogDriver != ecsapi.LogDriverAWSLOGS {
		return nil, fmt.Errorf("ECS task logging supports only the awslogs driver")
	}
	if len(config.SecretOptions) != 0 {
		return nil, fmt.Errorf("awslogs secretOptions are not supported")
	}
	for option := range config.Options {
		switch option {
		case "awslogs-region", "awslogs-group", "awslogs-stream-prefix", "awslogs-create-group", "mode", "max-buffer-size":
		default:
			return nil, fmt.Errorf("unsupported awslogs option %q", option)
		}
	}
	options := config.Options
	for _, required := range []ecsapi.String{"awslogs-region", "awslogs-group", "awslogs-stream-prefix"} {
		if options[required] == "" {
			return nil, fmt.Errorf("awslogs requires %s", required)
		}
	}
	if a.Logs == nil || a.Clock == nil || credentials == nil {
		return nil, fmt.Errorf("ECS task logging requires Logs, clock, and execution-role credentials")
	}
	mode := options["mode"]
	if mode == "" {
		// ECS changed its default on June 25, 2025. Any account-level override
		// must be resolved by the ECS service before invoking this adapter.
		mode = "non-blocking"
	}
	if mode != "blocking" && mode != "non-blocking" {
		return nil, fmt.Errorf("invalid awslogs mode %q", mode)
	}
	createGroup := false
	if value, present := options["awslogs-create-group"]; present {
		if value != "true" && value != "false" {
			return nil, fmt.Errorf("awslogs-create-group must be true or false")
		}
		createGroup = value == "true"
	}
	limit := int64(10 << 20)
	if value, present := options["max-buffer-size"]; present {
		if mode != "non-blocking" {
			return nil, fmt.Errorf("max-buffer-size requires non-blocking mode")
		}
		var err error
		limit, err = ecsLogBufferSize(string(value))
		if err != nil {
			return nil, err
		}
	}
	w := &ecsLogSink{
		provider: a, key: key, credentials: credentials,
		region: string(options["awslogs-region"]), group: api.LogGroupName(options["awslogs-group"]),
		stream:      api.LogStreamName(string(options["awslogs-stream-prefix"]) + "/" + container + "/" + key.ID),
		nonBlocking: mode == "non-blocking", limit: limit,
	}
	// Fargate requires initialization to succeed even in non-blocking mode.
	// Try the stream first: an existing group must not require CreateLogGroup.
	err := w.createStream(ctx)
	if err != nil && err.Code == "ResourceNotFoundException" && createGroup {
		command, cancel, authErr := w.command(ctx)
		if authErr != nil {
			return nil, fmt.Errorf("initialize awslogs credentials for %s: %w", key.ARN(), authErr)
		}
		_, groupErr := a.Logs.CreateLogGroup(command, &api.CreateLogGroupRequest{LogGroupName: &w.group})
		cancel()
		if groupErr != nil && groupErr.Code != "ResourceAlreadyExistsException" {
			return nil, fmt.Errorf("failed to create Cloudwatch log group: %w", groupErr)
		}
		err = w.createStream(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloudwatch log stream: %w", err)
	}
	if w.nonBlocking {
		w.wake = sync.NewCond(&w.mu)
		w.done = make(chan struct{})
		go w.drain()
	}
	return w, nil
}

// ecsLogBufferSize accepts Docker's binary byte units without depending on an
// engine client or permitting unbounded/overflowing queue sizes.
func ecsLogBufferSize(value string) (int64, error) {
	text := strings.ToLower(strings.TrimSpace(value))
	multiplier := int64(1)
	for i, suffix := range []string{"k", "m", "g", "t", "p"} {
		if strings.HasSuffix(text, suffix) || strings.HasSuffix(text, suffix+"b") {
			text = strings.TrimSuffix(strings.TrimSuffix(text, "b"), suffix)
			multiplier = int64(1) << (10 * (i + 1))
			break
		}
	}
	text = strings.TrimSuffix(text, "b")
	number, err := strconv.ParseFloat(text, 64)
	size := number * float64(multiplier)
	if err != nil || !(size >= 1 && size < float64(int64(^uint64(0)>>1))) {
		return 0, fmt.Errorf("invalid awslogs max-buffer-size %q", value)
	}
	return int64(size), nil
}

type ecsLogItem struct {
	ctx       context.Context
	message   []byte
	timestamp int64
	next      *ecsLogItem
}

type ecsLogSink struct {
	provider    ECSLogs
	key         ecs.TaskKey
	credentials ecs.TaskCredentialSource
	region      string
	group       api.LogGroupName
	stream      api.LogStreamName
	nonBlocking bool
	limit       int64

	mu      sync.Mutex
	closed  bool
	wake    *sync.Cond
	done    chan struct{}
	first   *ecsLogItem
	last    *ecsLogItem
	queued  int64
	failure error
}

func (w *ecsLogSink) command(ctx context.Context) (context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	credential, wire := w.credentials(ctx)
	if wire != nil {
		cancel()
		return nil, nil, wire
	}
	if credential.AccountID != w.key.AccountID {
		cancel()
		return nil, nil, fmt.Errorf("execution-role credential account differs from task %s", w.key.ARN())
	}
	command, err := serviceRoleRequestContext(ctx, credential, w.region, "ecs-tasks.amazonaws.com")
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return command, cancel, nil
}

func (w *ecsLogSink) createStream(ctx context.Context) *awswire.Error {
	command, cancel, err := w.command(ctx)
	if err != nil {
		if wire, ok := err.(*awswire.Error); ok {
			return wire
		}
		return &awswire.Error{Code: "UnrecognizedClientException", Message: err.Error(), StatusCode: 400}
	}
	defer cancel()
	_, wire := w.provider.Logs.CreateLogStream(command, &api.CreateLogStreamRequest{LogGroupName: &w.group, LogStreamName: &w.stream})
	if wire != nil && wire.Code == "ResourceAlreadyExistsException" {
		return nil
	}
	return wire
}

func (w *ecsLogSink) Write(ctx context.Context, record runtime.LogRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(record.Message) == 0 {
		return nil
	}
	timestamp := w.provider.Clock.Now().UnixMilli()
	if !w.nonBlocking {
		return w.deliver(ctx, record.Message, timestamp)
	}
	// Like the native ring, drop new output when the byte budget is full,
	// but admit one oversized record into an empty queue.
	// A native record's byte slice is borrowed only for this callback.
	if w.first != nil && int64(len(record.Message)) > w.limit-w.queued {
		return nil
	}
	item := &ecsLogItem{ctx: context.WithoutCancel(ctx), message: bytes.Clone(record.Message), timestamp: timestamp}
	if w.last == nil {
		w.first = item
	} else {
		w.last.next = item
	}
	w.last = item
	w.queued += int64(len(item.message))
	w.wake.Signal()
	return nil
}

func (w *ecsLogSink) drain() {
	defer close(w.done)
	for {
		w.mu.Lock()
		for w.first == nil && !w.closed {
			w.wake.Wait()
		}
		if w.first == nil {
			w.mu.Unlock()
			return
		}
		item := w.first
		w.first = item.next
		if w.first == nil {
			w.last = nil
		}
		w.queued -= int64(len(item.message))
		w.mu.Unlock()
		if err := w.deliver(item.ctx, item.message, item.timestamp); err != nil {
			w.mu.Lock()
			w.failure = err
			w.mu.Unlock()
			slog.Warn("ECS log delivery failed", "task", w.key.ARN(), "log_group", w.group, "log_stream", w.stream, "error", err)
		}
	}
}

func (w *ecsLogSink) Close() error {
	w.mu.Lock()
	w.closed = true
	if w.nonBlocking {
		w.wake.Signal()
	}
	w.mu.Unlock()
	if w.nonBlocking {
		<-w.done
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failure
}

func (w *ecsLogSink) deliver(ctx context.Context, data []byte, timestamp int64) error {
	var events api.InputLogEvents
	size := 0
	flush := func() error {
		if len(events) == 0 {
			return nil
		}
		command, cancel, err := w.command(ctx)
		if err != nil {
			return err
		}
		defer cancel()
		_, wire := w.provider.Logs.PutLogEvents(command, &api.PutLogEventsRequest{LogGroupName: &w.group, LogStreamName: &w.stream, LogEvents: events})
		if wire != nil {
			return fmt.Errorf("failed to put Cloudwatch log events: %w", wire)
		}
		events = events[:0]
		size = 0
		return nil
	}
	// Engine records delimit output, including a final unterminated line. LF
	// separators are not part of native awslogs events; CR is ordinary content.
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		message := string(line)
		if !utf8.ValidString(message) {
			// JSON/native awslogs replaces each invalid byte with U+FFFD.
			message = strings.Map(func(r rune) rune { return r }, message)
		}
		for len(message) > 0 {
			end := min(len(message), ecsLogEventBytes)
			for end < len(message) && !utf8.RuneStart(message[end]) {
				end--
			}
			if len(events) == logs.MaxBatchEvents || size+end+logs.EventOverheadBytes > logs.MaxBatchBytes {
				if err := flush(); err != nil {
					return err
				}
			}
			events = append(events, api.InputLogEvent{Message: new(api.EventMessage(message[:end])), Timestamp: new(api.Timestamp(timestamp))})
			size += end + logs.EventOverheadBytes
			message = message[end:]
		}
	}
	return flush()
}
