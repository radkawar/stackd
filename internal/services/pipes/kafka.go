package pipes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// KafkaSources opens real coordinator-owned consumers. Deleting a pipe may
// remove only its generated group; a supplied group always remains caller-owned.
type KafkaSources interface {
	Open(context.Context, PipeRecord, KafkaIdentity) (KafkaConsumer, error)
	Delete(context.Context, PipeRecord) error
}

// KafkaConsumer keeps coordinator membership separate from durable target work.
// Offsets are NEXT offsets, exactly as in the Kafka protocol. Assignments and
// Lease fence all fetch/target/commit work to the current native generation.
// Implementations reauthorize through the current execution role on each call.
type KafkaConsumer interface {
	Identity(context.Context) (KafkaIdentity, error)
	Assignments(context.Context) ([]KafkaPartition, error)
	Fetch(context.Context, int, int64, int) (KafkaPage, error)
	Commit(context.Context, map[int]int64) error
	Lease(context.Context, int) (context.Context, context.CancelFunc, error)
	Close() error
}
type KafkaPartition struct {
	ID        int
	Offset    int64
	Committed bool
}
type KafkaPage struct {
	Records []KafkaRecord
	// NextOffset advances only the retained fetch cursor, never the group commit.
	NextOffset int64
}
type KafkaRecord struct {
	Partition     int
	Offset        int64
	Timestamp     time.Time
	TimestampType string
	Key, Value    []byte
	Headers       []KafkaHeader
}
type KafkaHeader struct {
	Key   string
	Value []byte
}

// KafkaIdentity binds all work and cursors of one pipe to native source metadata.
// It is retained independently of mutable configuration and never rebound.
type KafkaIdentity struct {
	ClusterID, TopicID string
}

var ErrKafkaSourceChanged = errors.New("kafka source changed; retained work and cursors belong to a different native cluster or topic; recreate the pipe to consume the replacement")

func (s *Service) kafkaConsumer(ctx context.Context, p PipeRecord) (KafkaConsumer, error) {
	s.kafkaMu.Lock()
	defer s.kafkaMu.Unlock()
	if c := s.kafka[p.ID]; c != nil {
		return c, nil
	}
	if s.kafkaSources == nil {
		return nil, unsupported("Kafka requires a real configured consumer adapter.")
	}
	var identity KafkaIdentity
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		identity, err = r.KafkaIdentity(p.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	c, err := s.kafkaSources.Open(ctx, p, identity)
	if err != nil {
		return nil, err
	}
	actual, err := c.Identity(ctx)
	if err == nil {
		err = s.repository.Update(ctx, func(t Transaction) error {
			return bindKafkaIdentity(t, p.ID, actual)
		})
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	s.kafka[p.ID] = c
	return c, nil
}

func bindKafkaIdentity(t Transaction, id string, actual KafkaIdentity) error {
	if actual.ClusterID == "" || actual.TopicID == "" {
		return errors.New("kafka source requires native cluster and topic IDs")
	}
	if _, err := t.PipeByID(id); err != nil {
		return err
	}
	retained, err := t.KafkaIdentity(id)
	if err != nil {
		return err
	}
	if retained != (KafkaIdentity{}) {
		if retained != actual {
			return ErrKafkaSourceChanged
		}
		return nil
	}
	// Never bless identity-less retained offsets with the currently visible topic.
	work, err := t.Work(id)
	if err != nil {
		return err
	}
	checkpoints, err := t.Checkpoints(id)
	if err != nil {
		return err
	}
	if len(work) != 0 || len(checkpoints) != 0 {
		return ErrKafkaSourceChanged
	}
	return t.PutKafkaIdentity(id, actual)
}
func (s *Service) closeKafka(id string) error {
	s.kafkaMu.Lock()
	c := s.kafka[id]
	delete(s.kafka, id)
	s.kafkaMu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}

func kafkaPartitionOffset(p KafkaPartition, cps []Checkpoint) int64 {
	offset := p.Offset
	if !p.Committed {
		for _, cp := range cps {
			if cp.ShardID == strconv.Itoa(p.ID) && cp.Initialized {
				if last, err := strconv.ParseInt(cp.Sequence, 10, 64); err == nil {
					return last + 1
				}
			}
		}
	}
	return offset
}

// A revoked partition is never delivered by this member. Committed native
// offsets supersede retained work after another member has taken ownership.
func kafkaAssignedWork(work []Work, partitions []KafkaPartition) ([]Work, []Work) {
	assigned := make(map[string]KafkaPartition, len(partitions))
	for _, p := range partitions {
		assigned[strconv.Itoa(p.ID)] = p
	}
	ready, obsolete := make([]Work, 0, len(work)), []Work{}
	for _, w := range work {
		p, ok := assigned[w.ShardID]
		if !ok {
			continue
		}
		offset, err := strconv.ParseInt(w.Sequence, 10, 64)
		if err != nil {
			continue
		}
		if p.Committed && offset < p.Offset {
			obsolete = append(obsolete, w)
		} else {
			ready = append(ready, w)
		}
	}
	return ready, obsolete
}
func (s *Service) kafkaWork(ctx context.Context, p PipeRecord, work []Work) ([]Work, error) {
	c, err := s.kafkaConsumer(ctx, p)
	if err != nil {
		return nil, err
	}
	partitions, err := c.Assignments(ctx)
	if err != nil {
		return nil, err
	}
	assigned, obsolete := kafkaAssignedWork(work, partitions)
	if len(obsolete) != 0 {
		err = s.repository.Update(ctx, func(t Transaction) error {
			for _, w := range obsolete {
				if w.Phase == "executing" {
					continue
				}
				if err := t.DeleteWork(w.ID); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return assigned, err
}

func (s *Service) acquireKafka(ctx context.Context, p PipeRecord, work []Work, checkpoints []Checkpoint) error {
	c, err := s.kafkaConsumer(ctx, p)
	if err != nil {
		return s.delay(ctx, p, err.Error())
	}
	partitions, err := c.Assignments(ctx)
	if err != nil {
		return s.delay(ctx, p, err.Error())
	}
	cps := make(map[string]Checkpoint, len(checkpoints))
	for _, cp := range checkpoints {
		cps[cp.ShardID] = cp
	}
	ordinal := s.clock.Now().UnixNano()
	for _, w := range work {
		ordinal = max(ordinal, w.Ordinal+1)
	}
	accepted := []Work{}
	for _, partition := range partitions {
		shard := strconv.Itoa(partition.ID)
		offset := kafkaPartitionOffset(partition, checkpoints)
		cp, exists := cps[shard]
		if !exists {
			cp = Checkpoint{PipeID: p.ID, ShardID: shard, Sequence: strconv.FormatInt(offset-1, 10), Initialized: true}
		}
		if last, e := strconv.ParseInt(cp.Sequence, 10, 64); e == nil {
			offset = max(offset, last+1)
		}
		if cursor, e := strconv.ParseInt(cp.Iterator, 10, 64); e == nil {
			offset = max(offset, cursor)
		}
		pending := 0
		for _, w := range work {
			if w.ShardID != shard {
				continue
			}
			pending++
			last, e := strconv.ParseInt(w.Sequence, 10, 64)
			if e != nil {
				return e
			}
			offset = max(offset, last+1)
		}
		cps[shard] = cp
		if pending >= int(p.Source.BatchSize) {
			continue
		}
		page, e := c.Fetch(ctx, partition.ID, offset, int(p.Source.BatchSize)-pending)
		if e != nil {
			return s.delay(ctx, p, e.Error())
		}
		cp.Iterator = strconv.FormatInt(page.NextOffset, 10)
		cps[shard] = cp
		for _, record := range page.Records {
			event, e := kafkaEvent(p, record)
			if e != nil {
				return e
			}
			sequence := strconv.FormatInt(record.Offset, 10)
			w := Work{ID: uuid.NewString(), PipeID: p.ID, ShardID: shard, Sequence: sequence, RecordID: p.Source.Kafka.Topic + "-" + shard + ":" + sequence, Event: event, Created: record.Timestamp, Ordinal: ordinal, Phase: "ready", Due: s.clock.Now().Add(time.Duration(p.Source.WindowSeconds) * time.Second)}
			ordinal++
			matched, e := matchesKafka(p.Source.Filters, event)
			if e != nil {
				return e
			}
			w.Filtered = !matched
			accepted = append(accepted, w)
		}
	}
	retained := make([]Checkpoint, 0, len(cps))
	for _, cp := range cps {
		retained = append(retained, cp)
	}
	return s.retain(ctx, p, accepted, retained)
}

func (s *Service) commitKafka(ctx context.Context, p PipeRecord, batch []Work) error {
	c, err := s.kafkaConsumer(ctx, p)
	if err != nil {
		return err
	}
	offsets := make(map[int]int64)
	for _, w := range batch {
		partition, e := strconv.Atoi(w.ShardID)
		if e != nil {
			return e
		}
		offset, e := strconv.ParseInt(w.Sequence, 10, 64)
		if e != nil {
			return e
		}
		offsets[partition] = max(offsets[partition], offset+1)
	}
	return c.Commit(ctx, offsets)
}

func kafkaEvent(p PipeRecord, r KafkaRecord) ([]byte, error) {
	headers := make([]map[string][]int, 0, len(r.Headers))
	for _, h := range r.Headers {
		bytes := make([]int, len(h.Value))
		for i, v := range h.Value {
			bytes[i] = int(v)
		}
		headers = append(headers, map[string][]int{h.Key: bytes})
	}
	event := map[string]any{"eventSourceKey": fmt.Sprintf("%s-%d", p.Source.Kafka.Topic, r.Partition), "topic": p.Source.Kafka.Topic, "partition": r.Partition, "offset": r.Offset, "timestamp": r.Timestamp.UnixMilli(), "timestampType": r.TimestampType, "headers": headers}
	if r.Key == nil {
		event["key"] = nil
	} else {
		event["key"] = base64.StdEncoding.EncodeToString(r.Key)
	}
	if r.Value == nil {
		event["value"] = nil
	} else {
		event["value"] = base64.StdEncoding.EncodeToString(r.Value)
	}
	if p.Source.Kind == "msk" {
		event["eventSource"], event["eventSourceArn"], event["partition"] = "aws:kafka", p.SourceARN, strconv.Itoa(r.Partition)
	} else {
		event["eventSource"] = "SelfManagedKafka"
		event["bootstrapServers"] = strings.Join(append([]string{strings.TrimPrefix(p.SourceARN, "smk://")}, p.Source.Kafka.BootstrapServers...), ",")
	}
	return json.Marshal(event)
}

func (s *Service) kafkaLease(ctx context.Context, p PipeRecord, batch []Work) (context.Context, context.CancelFunc, error) {
	c, err := s.kafkaConsumer(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	if len(batch) == 0 {
		return nil, nil, errors.New("kafka delivery requires a partition batch")
	}
	partition, err := strconv.Atoi(batch[0].ShardID)
	if err != nil {
		return nil, nil, err
	}
	return c.Lease(ctx, partition)
}
