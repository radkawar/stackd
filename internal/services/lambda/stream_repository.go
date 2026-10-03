package lambda

import (
	"encoding/json"
	"slices"
	"time"
)

// Checkpoint is the last atomically captured source sequence, not an execution
// acknowledgement. Queued records and retry boundaries own execution recovery.
type StreamShardKey struct {
	Mapping EventSourceMappingKey
	ShardID string
}
type StreamShardRecord struct {
	Key                                    StreamShardKey
	ParentID, AdjacentParentID, Checkpoint string
	StartingPositionTimestamp              time.Time
	Retention                              time.Duration
	ReadComplete, Complete                 bool
	Lanes                                  []StreamLane
}
type StreamLane struct {
	Records                  []StreamQueuedRecord
	Batches                  []StreamBatch
	WindowStart, WindowEnd   time.Time
	WindowState              json.RawMessage
	WindowFinal, WindowEarly bool
}
type StreamQueuedRecord struct {
	ID, Sequence, ItemKey string
	CreatedAt, CapturedAt time.Time
	Payload               json.RawMessage
}
type StreamBatch struct {
	Count, Attempts                                            int
	Due                                                        time.Time
	LastEventID, LastRequestID, ExecutedVersion, FunctionError string
	InvokeCount                                                int
}
type StreamReader interface {
	StreamShards(EventSourceMappingKey) ([]StreamShardRecord, error)
	StreamFailures() ([]StreamFailure, error)
}
type StreamWriter interface {
	// PutStreamShard returns ErrNotFound after mapping deletion; completion
	// may still retain independent failure-destination work.
	PutStreamShard(StreamShardRecord) error
	PutStreamFailure(StreamFailure) error
	DeleteStreamFailure(string) error
}

func cloneStreamShard(v StreamShardRecord) StreamShardRecord {
	v.Lanes = slices.Clone(v.Lanes)
	for i := range v.Lanes {
		lane := &v.Lanes[i]
		lane.Records = slices.Clone(lane.Records)
		for j := range lane.Records {
			lane.Records[j].Payload = slices.Clone(lane.Records[j].Payload)
		}
		lane.Batches = slices.Clone(lane.Batches)
		lane.WindowState = slices.Clone(lane.WindowState)
	}
	return v
}
