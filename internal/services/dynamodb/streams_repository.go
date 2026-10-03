package dynamodb

import (
	"cmp"
	api "stackd/internal/awsapi/dynamodbstreams"
	"strings"
	"time"
)

// StreamGeneration outlives its table, retaining the opaque native identity.
// ClosedAt starts the public retention deadline, independently of the host clock.
type StreamGeneration struct {
	Key                                        PolicyKey
	Table                                      TableKey
	DatabaseID, PhysicalName, NativeARN, Label string
	CreatedAt, ClosedAt                        time.Time
	ViewType                                   api.StreamViewType
	KeySchema                                  api.KeySchema
}
type StreamShard struct {
	StreamARN, ID, ParentID, Start, End string
	// Checkpoint advances in the same transaction as copied native records.
	Checkpoint, TrimmedThrough string
	Drained                    bool
}
type StreamEntry struct {
	StreamARN, ShardID, Sequence string
	CreatedAt                    time.Time
	Data                         api.Record
}

// StreamEntryQuery selects a numeric sequence range, capped at 1000 records and
// 1 MiB of native SizeBytes before payloads are copied or decoded.
type StreamEntryQuery struct {
	StreamARN, ShardID, Position string
	Inclusive                    bool
	Limit                        int
}

func compareSequence(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	return cmp.Or(cmp.Compare(len(a), len(b)), cmp.Compare(a, b))
}
func cloneStream(v StreamGeneration) StreamGeneration {
	v.KeySchema = api.CloneKeySchema(v.KeySchema)
	return v
}
func streamExpired(v StreamGeneration, now time.Time) bool {
	return !v.ClosedAt.IsZero() && !now.Before(v.ClosedAt.Add(24*time.Hour))
}
