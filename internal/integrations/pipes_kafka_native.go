package integrations

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/protocol"
	fetchapi "github.com/segmentio/kafka-go/protocol/fetch"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
	franzsasl "github.com/twmb/franz-go/pkg/sasl"
	"stackd/internal/services/pipes"
)

// Only Kafka protocol membership/heartbeats run in the native goroutine. Source
// polling, retries and target effects remain on the shared Pipes job driver.
type pipesKafkaMember struct {
	topic             string
	client            *kafka.Client
	transport         *kafka.Transport
	metadata          *kgo.Client
	identity          pipes.KafkaIdentity
	startingTimestamp time.Time
	group             *kafka.ConsumerGroup
	ctx               context.Context
	cancel            context.CancelFunc
	done              chan struct{}
	mu                sync.Mutex
	changed           chan struct{}
	generation        *kafka.Generation
	generationContext context.Context
	positions         map[int]pipes.KafkaPartition
	lastError         error
}

type kafkaMemberConfig struct {
	topic, groupID, clientID, startingPosition string
	startingTimestamp                          time.Time
	dial                                       func(context.Context, string, string) (net.Conn, error)
}

func newPipesKafkaMember(ctx context.Context, source kafkaMemberConfig, access pipesKafkaAccess) (*pipesKafkaMember, error) {
	config, mechanism, err := access.security()
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	transport := &kafka.Transport{Context: lifetime, ClientID: source.clientID, TLS: config, SASL: mechanism, DialTimeout: 5 * time.Second, Dial: source.dial}
	client := &kafka.Client{Addr: kafka.TCP(access.brokers...), Transport: transport}
	options := []kgo.Opt{kgo.SeedBrokers(access.brokers...), kgo.ClientID(source.clientID), kgo.RequestRetries(0)}
	if config != nil {
		options = append(options, kgo.DialTLSConfig(config))
	}
	if source.dial != nil {
		options = append(options, kgo.Dialer(func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := source.dial(ctx, network, address)
			if err != nil || config == nil {
				return connection, err
			}
			security := config.Clone()
			if security.ServerName == "" {
				security.ServerName, _, err = net.SplitHostPort(address)
				if err != nil {
					connection.Close()
					return nil, err
				}
			}
			secured := tls.Client(connection, security)
			if err := secured.HandshakeContext(ctx); err != nil {
				connection.Close()
				return nil, err
			}
			return secured, nil
		}))
	}
	if mechanism != nil {
		options = append(options, kgo.SASL(pipesKafkaSASL{mechanism}))
	}
	metadata, err := kgo.NewClient(options...)
	if err != nil {
		cancel()
		transport.CloseIdleConnections()
		return nil, err
	}
	member := &pipesKafkaMember{topic: source.topic, startingTimestamp: source.startingTimestamp, client: client, transport: transport, metadata: metadata, ctx: lifetime, cancel: cancel, done: make(chan struct{}), changed: make(chan struct{})}
	member.identity, err = member.sourceIdentity(ctx)
	if err != nil {
		cancel()
		metadata.Close()
		transport.CloseIdleConnections()
		return nil, err
	}
	start := kafka.FirstOffset
	if source.startingPosition == "LATEST" {
		start = kafka.LastOffset
	}
	group, err := kafka.NewConsumerGroup(kafka.ConsumerGroupConfig{
		ID: source.groupID, Brokers: access.brokers, Topics: []string{source.topic}, StartOffset: int64(start),
		Dialer:                &kafka.Dialer{Timeout: 5 * time.Second, TLS: config, SASLMechanism: mechanism, ClientID: source.clientID, DialFunc: source.dial},
		WatchPartitionChanges: true,
	})
	if err != nil {
		cancel()
		metadata.Close()
		transport.CloseIdleConnections()
		return nil, err
	}
	member.group = group
	go member.run()
	return member, nil
}
func (m *pipesKafkaMember) signal() { close(m.changed); m.changed = make(chan struct{}) }
func (m *pipesKafkaMember) run() {
	defer close(m.done)
	for {
		generation, err := m.group.Next(m.ctx)
		if m.ctx.Err() != nil || errors.Is(err, kafka.ErrGroupClosed) {
			return
		}
		if err != nil {
			m.mu.Lock()
			m.lastError = err
			m.signal()
			m.mu.Unlock()
			continue
		}
		generation.Start(func(ctx context.Context) {
			m.mu.Lock()
			m.generation, m.generationContext, m.positions, m.lastError = generation, ctx, nil, nil
			m.signal()
			m.mu.Unlock()
			<-ctx.Done()
			m.mu.Lock()
			if m.generation == generation {
				m.generation, m.generationContext, m.positions = nil, nil, nil
				m.signal()
			}
			m.mu.Unlock()
		})
	}
}
func (m *pipesKafkaMember) close() error {
	m.cancel()
	err := m.group.Close()
	<-m.done
	m.transport.CloseIdleConnections()
	m.metadata.Close()
	return err
}
func (m *pipesKafkaMember) snapshot(ctx context.Context) (*kafka.Generation, context.Context, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		m.mu.Lock()
		generation, generationContext, changed, lastError := m.generation, m.generationContext, m.changed, m.lastError
		m.mu.Unlock()
		if generation != nil && generationContext.Err() == nil {
			return generation, generationContext, nil
		}
		if lastError != nil {
			var temporary interface{ Temporary() bool }
			if !errors.As(lastError, &temporary) || !temporary.Temporary() {
				return nil, nil, lastError
			}
			// ConsumerGroup owns coordinator discovery and its native backoff.
			// Wait for that attempt rather than failing pipe creation while
			// Kafka is initializing __consumer_offsets.
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-m.ctx.Done():
			return nil, nil, m.ctx.Err()
		case <-changed:
		}
	}
}
func kafkaGenerationContext(ctx, generation context.Context, lifetime context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	stopGeneration := context.AfterFunc(generation, cancel)
	stopLifetime := context.AfterFunc(lifetime, cancel)
	return ctx, func() { stopGeneration(); stopLifetime(); cancel() }
}
func (m *pipesKafkaMember) lease(ctx context.Context, partition int) (context.Context, context.CancelFunc, error) {
	generation, generationContext, err := m.snapshot(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, assigned := range generation.Assignments[m.topic] {
		if assigned.ID == partition {
			ctx, cancel := kafkaGenerationContext(ctx, generationContext, m.ctx)
			if generationContext.Err() != nil {
				cancel()
				return nil, nil, kafka.ErrGenerationEnded
			}
			return ctx, cancel, nil
		}
	}
	return nil, nil, errors.New("kafka partition is not assigned to this consumer")
}
func (m *pipesKafkaMember) assignments(ctx context.Context) ([]pipes.KafkaPartition, error) {
	generation, generationContext, err := m.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	cached := m.generation == generation && m.positions != nil
	if cached {
		out := make([]pipes.KafkaPartition, 0, len(m.positions))
		for _, p := range m.positions {
			out = append(out, p)
		}
		m.mu.Unlock()
		slices.SortFunc(out, func(a, b pipes.KafkaPartition) int { return a.ID - b.ID })
		return out, nil
	}
	m.mu.Unlock()
	ctx, release := kafkaGenerationContext(ctx, generationContext, m.ctx)
	defer release()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	positions := make(map[int]pipes.KafkaPartition)
	for _, assigned := range generation.Assignments[m.topic] {
		p := pipes.KafkaPartition{ID: assigned.ID, Offset: assigned.Offset, Committed: assigned.Offset >= 0}
		if !p.Committed {
			if !m.startingTimestamp.IsZero() {
				p.Offset = m.startingTimestamp.UnixMilli()
			}
			requests := []kafka.OffsetRequest{{Partition: p.ID, Timestamp: p.Offset}}
			if !m.startingTimestamp.IsZero() {
				requests = append(requests, kafka.LastOffsetOf(p.ID))
			}
			offsets, err := m.client.ListOffsets(ctx, &kafka.ListOffsetsRequest{Topics: map[string][]kafka.OffsetRequest{m.topic: requests}, IsolationLevel: kafka.ReadCommitted})
			if err != nil {
				return nil, err
			}
			results := offsets.Topics[m.topic]
			if len(results) != 1 || results[0].Partition != p.ID {
				return nil, errors.New("kafka offset response omitted source partition")
			}
			if results[0].Error != nil {
				return nil, results[0].Error
			}
			if p.Offset == kafka.FirstOffset {
				p.Offset = results[0].FirstOffset
			} else if m.startingTimestamp.IsZero() {
				p.Offset = results[0].LastOffset
			} else {
				p.Offset = results[0].LastOffset
				for offset := range results[0].Offsets {
					if offset >= 0 {
						p.Offset = offset
					}
				}
			}
		}
		positions[p.ID] = p
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.generation != generation || generationContext.Err() != nil {
		return nil, kafka.ErrGenerationEnded
	}
	if m.positions == nil {
		m.positions = positions
	}
	out := make([]pipes.KafkaPartition, 0, len(m.positions))
	for _, p := range m.positions {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b pipes.KafkaPartition) int { return a.ID - b.ID })
	return out, nil
}
func (m *pipesKafkaMember) commit(ctx context.Context, offsets map[int]int64) error {
	generation, generationContext, err := m.snapshot(ctx)
	if err != nil {
		return err
	}
	commits := make([]kafka.OffsetCommit, 0, len(offsets))
	for partition, offset := range offsets {
		owned := false
		for _, assigned := range generation.Assignments[m.topic] {
			if assigned.ID == partition {
				owned = true
				offset = max(offset, assigned.Offset)
			}
		}
		if !owned {
			return errors.New("cannot commit an unassigned Kafka partition")
		}
		m.mu.Lock()
		if p, ok := m.positions[partition]; ok && p.Committed {
			offset = max(offset, p.Offset)
		}
		m.mu.Unlock()
		commits = append(commits, kafka.OffsetCommit{Partition: partition, Offset: offset})
	}
	ctx, release := kafkaGenerationContext(ctx, generationContext, m.ctx)
	defer release()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := m.client.OffsetCommit(ctx, &kafka.OffsetCommitRequest{GroupID: generation.GroupID, GenerationID: int(generation.ID), MemberID: generation.MemberID, Topics: map[string][]kafka.OffsetCommit{m.topic: commits}})
	if err != nil {
		return err
	}
	results := response.Topics[m.topic]
	for _, commit := range commits {
		found := false
		for _, result := range results {
			if result.Partition == commit.Partition {
				found = true
				if result.Error != nil {
					return result.Error
				}
			}
		}
		if !found {
			return errors.New("kafka commit response omitted source partition")
		}
	}
	m.mu.Lock()
	if m.generation == generation && m.positions != nil {
		for _, c := range commits {
			m.positions[c.Partition] = pipes.KafkaPartition{ID: c.Partition, Offset: c.Offset, Committed: true}
		}
	}
	m.mu.Unlock()
	return nil
}

func (m *pipesKafkaMember) fetch(ctx context.Context, partition int, offset int64, limit int) (pipes.KafkaPage, error) {
	page := pipes.KafkaPage{NextOffset: offset}
	if offset < 0 || limit < 1 {
		return page, errors.New("kafka fetch requires a nonnegative offset and positive limit")
	}
	ctx, release, err := m.lease(ctx, partition)
	if err != nil {
		return page, err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := m.transport.RoundTrip(ctx, m.client.Addr, &fetchapi.Request{
		ReplicaID: -1, MaxWaitTime: 100, MinBytes: 1, MaxBytes: 4 * 1024 * 1024, IsolationLevel: int8(kafka.ReadCommitted), SessionID: -1, SessionEpoch: -1,
		Topics: []fetchapi.RequestTopic{{Topic: m.topic, Partitions: []fetchapi.RequestPartition{{Partition: int32(partition), CurrentLeaderEpoch: -1, FetchOffset: offset, LogStartOffset: -1, PartitionMaxBytes: 4 * 1024 * 1024}}}},
	})
	if err != nil {
		return page, err
	}
	result := response.(*fetchapi.Response)
	if result.ErrorCode != 0 {
		return page, kafka.Error(result.ErrorCode)
	}
	if len(result.Topics) != 1 || result.Topics[0].Topic != m.topic || len(result.Topics[0].Partitions) != 1 || int(result.Topics[0].Partitions[0].Partition) != partition {
		return page, errors.New("kafka fetch response omitted source partition")
	}
	part := result.Topics[0].Partitions[0]
	if part.ErrorCode != 0 {
		return page, kafka.Error(part.ErrorCode)
	}
	reader := pipesKafkaRead{page: page, partition: partition, offset: offset, limit: limit, aborted: make(map[int64][]int64, len(part.AbortedTransactions))}
	for _, transaction := range part.AbortedTransactions {
		reader.aborted[transaction.ProducerID] = append(reader.aborted[transaction.ProducerID], transaction.FirstOffset)
	}
	if part.RecordSet.Records != nil {
		if err = reader.read(part.RecordSet.Records, "CREATE_TIME", false); err != nil {
			return page, err
		}
	}
	// Empty stable ranges arise from compaction/transaction markers. Retain the
	// read cursor, not a group commit; failed target work still fences all acks.
	if reader.page.NextOffset == offset && len(reader.page.Records) == 0 {
		reader.page.NextOffset = max(offset, part.LastStableOffset)
	}
	if ctx.Err() != nil {
		return page, ctx.Err()
	}
	return reader.page, nil
}

// kafka-go's Metadata v8 cannot return topic UUIDs. Use upstream generated
// Metadata v10+ without a second consumer group or a custom wire parser.
func (m *pipesKafkaMember) sourceIdentity(ctx context.Context) (pipes.KafkaIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request := kmsg.NewPtrMetadataRequest()
	request.Topics = []kmsg.MetadataRequestTopic{{Topic: &m.topic}}
	response, err := request.RequestWith(ctx, m.metadata)
	if err != nil {
		return pipes.KafkaIdentity{}, err
	}
	return kafkaMetadataIdentity(m.topic, response)
}

func kafkaMetadataIdentity(topic string, response *kmsg.MetadataResponse) (pipes.KafkaIdentity, error) {
	if response.Version < 10 || response.ClusterID == nil || *response.ClusterID == "" {
		return pipes.KafkaIdentity{}, errors.New("kafka source requires Metadata v10+ with native cluster and topic IDs")
	}
	if len(response.Topics) != 1 || response.Topics[0].Topic == nil || *response.Topics[0].Topic != topic {
		return pipes.KafkaIdentity{}, errors.New("kafka metadata omitted source topic")
	}
	source := response.Topics[0]
	if source.ErrorCode != 0 {
		return pipes.KafkaIdentity{}, kafka.Error(source.ErrorCode)
	}
	for _, partition := range source.Partitions {
		if partition.ErrorCode != 0 {
			return pipes.KafkaIdentity{}, kafka.Error(partition.ErrorCode)
		}
	}
	if source.TopicID == ([16]byte{}) {
		return pipes.KafkaIdentity{}, errors.New("kafka source omitted native topic ID; identity-less brokers are unsupported")
	}
	return pipes.KafkaIdentity{ClusterID: *response.ClusterID, TopicID: fmt.Sprintf("%x", source.TopicID)}, nil
}

// Reuse the already validated security settings and SASL implementation.
type pipesKafkaSASL struct{ sasl.Mechanism }

func (m pipesKafkaSASL) Authenticate(ctx context.Context, _ string) (franzsasl.Session, []byte, error) {
	state, first, err := m.Start(ctx)
	return pipesKafkaSASLSession{ctx: ctx, state: state}, first, err
}

type pipesKafkaSASLSession struct {
	ctx   context.Context
	state sasl.StateMachine
}

func (s pipesKafkaSASLSession) Challenge(challenge []byte) (bool, []byte, error) {
	return s.state.Next(s.ctx, challenge)
}

type pipesKafkaRead struct {
	page             pipes.KafkaPage
	partition, limit int
	offset           int64
	aborted          map[int64][]int64
}

func (r *pipesKafkaRead) read(reader protocol.RecordReader, timestampType string, skip bool) error {
	switch batch := reader.(type) {
	case *protocol.RecordStream:
		for _, records := range batch.Records {
			if len(r.page.Records) >= r.limit {
				break
			}
			if err := r.read(records, timestampType, skip); err != nil {
				return err
			}
		}
		return nil
	case *protocol.ControlBatch:
		if starts := r.aborted[batch.ProducerID]; len(starts) > 0 && starts[0] <= batch.BaseOffset {
			r.aborted[batch.ProducerID] = starts[1:]
		}
		return r.read(batch.Records, timestampType, true)
	case *protocol.RecordBatch:
		starts := r.aborted[batch.ProducerID]
		skip = skip || len(starts) > 0 && batch.Attributes.Transactional() && batch.BaseOffset >= starts[0]
		if batch.Attributes&8 != 0 {
			timestampType = "LOG_APPEND_TIME"
		}
		return r.read(batch.Records, timestampType, skip)
	case *protocol.MessageSet:
		if batch.Attributes&8 != 0 {
			timestampType = "LOG_APPEND_TIME"
		}
		return r.read(batch.Records, timestampType, skip)
	}
	for len(r.page.Records) < r.limit {
		record, err := reader.ReadRecord()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		r.page.NextOffset = max(r.page.NextOffset, record.Offset+1)
		if record.Offset < r.offset || skip {
			if record.Key != nil {
				_ = record.Key.Close()
			}
			if record.Value != nil {
				_ = record.Value.Close()
			}
			continue
		}
		key, err := kafkaRecordBytes(record.Key)
		if err != nil {
			return err
		}
		value, err := kafkaRecordBytes(record.Value)
		if err != nil {
			return err
		}
		headers := make([]pipes.KafkaHeader, len(record.Headers))
		for i, h := range record.Headers {
			headers[i] = pipes.KafkaHeader{Key: h.Key, Value: slices.Clone(h.Value)}
		}
		r.page.Records = append(r.page.Records, pipes.KafkaRecord{Partition: r.partition, Offset: record.Offset, Timestamp: record.Time, TimestampType: timestampType, Key: key, Value: value, Headers: headers})
	}
	return nil
}
func kafkaRecordBytes(value protocol.Bytes) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	defer value.Close()
	return io.ReadAll(value)
}
