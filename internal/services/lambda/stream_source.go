package lambda

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/awswire"
)

// streamConsumer projects source-owned commands into retained Lambda work. Source
// adapters keep generated request types; this private boundary shares processing,
// not public APIs or source authorization.
type streamConsumer interface {
	Describe(context.Context) (streamDescription, error)
	LatestSequence(context.Context, string) (string, *awswire.Error)
	Read(context.Context, EventSourceMappingRecord, *StreamShardRecord, string, time.Time) (streamPage, error)
	Close()
}
type streamDescription struct {
	Shards    []streamShard
	Retention time.Duration
}
type streamShard struct {
	ID, ParentID, AdjacentParentID string
}
type streamPage struct {
	Records              []StreamQueuedRecord
	Checkpoint, Iterator string
	Complete             bool
}

func (s *Service) openStreamConsumer(ctx context.Context, function FunctionRecord, source string) (streamConsumer, *awswire.Error) {
	if strings.Contains(source, ":kinesis:") {
		if s.kinesis == nil {
			return nil, unsupported("Kinesis event source mappings require a Kinesis source adapter.")
		}
		consumer, wire := s.kinesis.Open(ctx, function.Key, function.Role, source)
		if wire != nil {
			return nil, wire
		}
		return &kinesisStreamConsumer{consumer: consumer, sourceARN: source, roleARN: function.Role, subscriptions: make(map[string]kinesisSubscription)}, nil
	}
	if s.dynamoDB == nil {
		return nil, unsupported("DynamoDB event source mappings require a DynamoDB Streams source adapter.")
	}
	consumer, wire := s.dynamoDB.Open(ctx, function.Key, function.Role, source)
	if wire != nil {
		return nil, wire
	}
	return &dynamoDBStreamConsumer{DynamoDBConsumer: consumer, sourceARN: source}, nil
}

func sourceWireError(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return wire
	}
	return failure("ServiceException", err.Error(), 500)
}

// StreamTargets delivers discarded batches through destination-owned commands.
// Acceptance does not imply downstream execution.
type StreamTargets interface {
	CheckStream(context.Context, FunctionKey, string, EventSourceMappingKey, string) *awswire.Error
	SendStream(context.Context, StreamFailure) *awswire.Error
}

// StreamFailure survives mapping/function deletion and retains the admitted
// role, destination and native document. Only S3 includes original event bytes.
type StreamFailure struct {
	ID                               string
	Mapping                          EventSourceMappingKey
	Function                         FunctionReference
	RoleARN, DestinationARN, ShardID string
	RecordCount                      int
	CreatedAt                        time.Time
	ParentEventID                    string
	Payload                          []byte
}
