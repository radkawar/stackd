package kinesis

import (
	"context"
	"strings"
	"sync"
	"time"

	"stackd/clock"
)

const (
	shardWriteBytesPerSecond = 1 << 20
	shardWriteBurstBytes     = 10 << 20
	shardReadBytesPerSecond  = 2 << 20
	admissionIdleTTL         = time.Minute
)

// These are local, replenishing budgets, not durable usage records. Limits come
// from https://docs.aws.amazon.com/streams/latest/dev/service-sizes-and-limits.html
// and https://docs.aws.amazon.com/kinesis/latest/APIReference/API_UpdateShardCount.html.
// AWS documents large-record burst capacity but not its exact allocator. The
// 10 MiB token bucket models that burst with the documented 1 MiB/s steady rate;
// the bounded native throughput capture did not measure a throttle boundary.
// TODO: Comeback — implement on-demand adaptive capacity from measured load;
// current stream modes share the documented per-shard provisioned budgets.
type admission struct {
	clock   clock.Clock
	mu      sync.Mutex
	budgets map[admissionKey]*admissionBudget
	oldest  *admissionBudget
	newest  *admissionBudget
}

type admissionKey struct {
	scope       Scope
	stream      string
	partition   int32
	incarnation string
	action      string
}

type admissionBudget struct {
	key           admissionKey
	previous      *admissionBudget
	next          *admissionBudget
	at            time.Time
	transactions  float64
	writeRecords  float64
	writeBytes    float64
	readCalls     float64
	iteratorCalls float64
	readBytes     float64
	readAfter     time.Time
}

func newAdmission(source clock.Clock) *admission {
	return &admission{clock: source, budgets: make(map[admissionKey]*admissionBudget)}
}

func shardAdmissionKey(shard ShardRecord) admissionKey {
	return admissionKey{
		scope: shard.Key.Stream.Scope, stream: shard.Key.Stream.Name,
		partition:   shard.Key.Partition,
		incarnation: value(shard.Data.SequenceNumberRange.StartingSequenceNumber),
	}
}

func (a *admission) unlink(b *admissionBudget) {
	if b.previous != nil {
		b.previous.next = b.next
	} else {
		a.oldest = b.next
	}
	if b.next != nil {
		b.next.previous = b.previous
	} else {
		a.newest = b.previous
	}
}

// budget is called only under mu. Expiration work is bounded per admission, not
// an unbounded map scan. Sustained traffic retires idle entries faster than it
// creates them; an idle service owns no background goroutines or timers. A read
// debt must have recovered before its entry can be discarded.
func (a *admission) budget(key admissionKey, now time.Time, tps float64) *admissionBudget {
	for i := 0; i < 8 && a.oldest != nil; i++ {
		b := a.oldest
		elapsed := now.Sub(b.at)
		if elapsed < admissionIdleTTL || now.Before(b.readAfter) || b.readBytes+elapsed.Seconds()*shardReadBytesPerSecond < shardReadBytesPerSecond {
			break
		}
		a.unlink(b)
		delete(a.budgets, b.key)
	}
	b := a.budgets[key]
	if b == nil {
		b = &admissionBudget{
			key: key, at: now, transactions: tps,
			writeRecords: 1000, writeBytes: shardWriteBurstBytes,
			readCalls: 5, iteratorCalls: 5, readBytes: shardReadBytesPerSecond,
		}
		a.budgets[key] = b
	} else {
		a.unlink(b)
		// A source clock can be rewound. Never replenish twice for the same
		// elapsed time or move a budget's accounting timestamp backwards.
		if now.After(b.at) {
			seconds := now.Sub(b.at).Seconds()
			if tps != 0 {
				b.transactions = min(tps, b.transactions+seconds*tps)
			} else {
				b.writeRecords = min(1000, b.writeRecords+seconds*1000)
				b.writeBytes = min(shardWriteBurstBytes, b.writeBytes+seconds*shardWriteBytesPerSecond)
				b.readCalls = min(5, b.readCalls+seconds*5)
				b.iteratorCalls = min(5, b.iteratorCalls+seconds*5)
				b.readBytes = min(shardReadBytesPerSecond, b.readBytes+seconds*shardReadBytesPerSecond)
			}
			b.at = now
		}
	}
	b.previous, b.next = a.newest, nil
	if a.newest != nil {
		a.newest.next = b
	} else {
		a.oldest = b
	}
	a.newest = b
	return b
}

func controlTPS(action string) (tps float64, perStream bool) {
	switch action {
	case "AddTagsToStream", "CreateStream", "DeleteResourcePolicy", "DeleteStream", "DescribeAccountSettings", "GetResourcePolicy", "ListStreams", "PutResourcePolicy", "UpdateAccountSettings", "UpdateStreamWarmThroughput":
		return 5, false
	case "DescribeLimits":
		return 1, false
	case "DescribeStream":
		return 10, false
	case "DescribeStreamSummary":
		return 20, false
	case "DecreaseStreamRetentionPeriod", "DeregisterStreamConsumer", "DisableEnhancedMonitoring", "EnableEnhancedMonitoring", "IncreaseStreamRetentionPeriod", "ListStreamConsumers", "ListTagsForStream", "MergeShards", "RegisterStreamConsumer", "RemoveTagsFromStream", "SplitShard":
		return 5, true
	case "DescribeStreamConsumer":
		return 20, true
	case "ListShards":
		return 1000, true
	case "UpdateShardCount":
		return 10, true
	default:
		// Data calls have shard budgets. SubscribeToShard belongs solely to
		// its consumer/shard lease. Daily mode/SSE/scaling limits live with
		// the stream state. No published TPS exists for UpdateMaxRecordSize.
		return 0, false
	}
}

func (s *Service) admitControl(ctx context.Context, action, resourceARN string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	call := currentCall(ctx)
	if call == nil || call.action != action || call.admitted {
		return nil
	}
	tps, perStream := controlTPS(action)
	if tps == 0 {
		call.admitted = true
		return nil
	}
	key := admissionKey{scope: scopeFor(ctx), action: action}
	if perStream {
		// Consumer operations share their parent's stream budget, not an
		// independent budget for each consumer. The ARN includes owner scope.
		key.scope = call.resource.Scope
		key.stream, _, _ = strings.Cut(resourceARN, "/consumer/")
	}
	a := s.admission
	a.mu.Lock()
	if err := ctx.Err(); err != nil {
		a.mu.Unlock()
		return err
	}
	b := a.budget(key, a.clock.Now(), tps)
	allowed := b.transactions >= 1
	if allowed {
		b.transactions--
		call.admitted = true
	}
	a.mu.Unlock()
	if !allowed {
		return failure("LimitExceededException", "Rate exceeded for "+action+".")
	}
	return nil
}

func (s *Service) admitWrite(ctx context.Context, _ StreamRecord, shard ShardRecord, bytes int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a := s.admission
	a.mu.Lock()
	if err := ctx.Err(); err != nil {
		a.mu.Unlock()
		return err
	}
	b := a.budget(shardAdmissionKey(shard), a.clock.Now(), 0)
	allowed := b.writeRecords >= 1 && b.writeBytes >= float64(bytes)
	if allowed {
		b.writeRecords--
		b.writeBytes -= float64(bytes)
	}
	a.mu.Unlock()
	if !allowed {
		s.dataSample(ctx, "WriteProvisionedThroughputExceeded", shard.Key.ID(), 1)
		return failure("ProvisionedThroughputExceededException", "Rate exceeded for shard "+shard.Key.ID()+" in stream "+shard.Key.Stream.Name+".")
	}
	s.dataSample(ctx, "WriteProvisionedThroughputExceeded", shard.Key.ID(), 0)
	return nil
}

func (s *Service) admitRead(ctx context.Context, shard ShardRecord, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if action != "GetRecords" && action != "GetShardIterator" {
		return nil
	}
	a := s.admission
	a.mu.Lock()
	if err := ctx.Err(); err != nil {
		a.mu.Unlock()
		return err
	}
	now := a.clock.Now()
	b := a.budget(shardAdmissionKey(shard), now, 0)
	allowed := false
	if action == "GetShardIterator" {
		allowed = b.iteratorCalls >= 1
		if allowed {
			b.iteratorCalls--
		}
	} else {
		allowed = b.readCalls >= 1 && b.readBytes > 0 && !now.Before(b.readAfter)
		if allowed {
			b.readCalls--
		}
	}
	a.mu.Unlock()
	if !allowed {
		if action == "GetRecords" {
			s.dataSample(ctx, "ReadProvisionedThroughputExceeded", shard.Key.ID(), 1)
		}
		return failure("ProvisionedThroughputExceededException", "Rate exceeded for shard "+shard.Key.ID()+" in stream "+shard.Key.Stream.Name+".")
	}
	if action == "GetRecords" {
		s.dataSample(ctx, "ReadProvisionedThroughputExceeded", shard.Key.ID(), 0)
	}
	return nil
}

// GetRecords cannot know its response size before native I/O. Charge the actual
// returned bytes, retaining debt for pages larger than the steady read allowance.
// A full 10 MiB page independently imposes the documented five-second cooldown.
// The existing openStreamRecord incarnation gate serializes this completion with
// the next shared-throughput read; the admission mutex never spans native I/O.
func (s *Service) observeReadBytes(shard ShardRecord, bytes int) {
	if bytes <= 0 {
		return
	}
	a := s.admission
	a.mu.Lock()
	now := a.clock.Now()
	b := a.budget(shardAdmissionKey(shard), now, 0)
	b.readBytes -= float64(bytes)
	if until := now.Add(5 * time.Second); bytes >= 10<<20 && until.After(b.readAfter) {
		b.readAfter = until
	}
	a.mu.Unlock()
}
