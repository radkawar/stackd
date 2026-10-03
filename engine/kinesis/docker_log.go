package kinesis

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/segmentio/kafka-go"
)

const (
	nativeTopic          = "owned-stream"
	nativeMaxBytes       = 12 << 20
	nativeRequestTimeout = 30 * time.Second
)

type nativeLog struct {
	client    *kafka.Client
	transport *kafka.Transport
	ctx       context.Context
	cancel    context.CancelFunc
}

var _ Log = (*nativeLog)(nil)

func newLog(endpoint string) *nativeLog {
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &kafka.Transport{
		Context:        ctx,
		ClientID:       "stackd-kinesis",
		MetadataTTL:    100 * time.Millisecond,
		MetadataTopics: []string{nativeTopic},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// A stream has exactly one broker. Resolve every advertised broker
			// address through its inspected owned endpoint, including remote
			// Docker loopback tunnels. Never dial a metadata-provided host.
			return dialer.DialContext(ctx, "tcp", endpoint)
		},
	}
	return &nativeLog{client: &kafka.Client{Addr: kafka.TCP(endpoint), Transport: transport}, transport: transport, ctx: ctx, cancel: cancel}
}

// operation is the single deadline/error boundary for all native log requests.
// Native errors remain discoverable with errors.Is/As; cancellation is not
// converted into a Kafka error, and failed writes are never replayed here.
func (l *nativeLog) operation(parent context.Context, name string, result *error) (context.Context, func()) {
	ctx, cancel := context.WithTimeout(parent, nativeRequestTimeout)
	stop := context.AfterFunc(l.ctx, cancel)
	if l.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() {
		if ctx.Err() != nil {
			*result = errors.Join(*result, ctx.Err())
		}
		if *result != nil {
			*result = fmt.Errorf("kafka %s: %w", name, *result)
		}
		stop()
		cancel()
	}
}

func (l *nativeLog) Close() error {
	l.cancel()
	l.transport.CloseIdleConnections()
	return nil
}

func topicConfiguration() []kafka.ConfigEntry {
	return []kafka.ConfigEntry{
		{ConfigName: "cleanup.policy", ConfigValue: "delete"},
		{ConfigName: "retention.ms", ConfigValue: "-1"},
		{ConfigName: "retention.bytes", ConfigValue: "-1"},
		{ConfigName: "flush.messages", ConfigValue: "1"},
		{ConfigName: "max.message.bytes", ConfigValue: "12582912"},
		{ConfigName: "message.timestamp.type", ConfigValue: "CreateTime"},
		{ConfigName: "message.timestamp.before.max.ms", ConfigValue: "9223372036854775807"},
		{ConfigName: "message.timestamp.after.max.ms", ConfigValue: "9223372036854775807"},
	}
}

func (l *nativeLog) ready(ctx context.Context) error {
	for {
		err := l.prepareTopic(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		var network net.Error
		var native kafka.Error
		if !errors.As(err, &network) && !(errors.As(err, &native) && native.Temporary()) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		if waitErr := pause(ctx); waitErr != nil {
			return errors.Join(err, waitErr)
		}
	}
}

func (l *nativeLog) prepareTopic(ctx context.Context) (err error) {
	ctx, finish := l.operation(ctx, "prepare topic", &err)
	defer finish()
	response, err := l.client.CreateTopics(ctx, &kafka.CreateTopicsRequest{Topics: []kafka.TopicConfig{{Topic: nativeTopic, NumPartitions: 1, ReplicationFactor: 1, ConfigEntries: topicConfiguration()}}})
	if err != nil {
		return err
	}
	topicErr, ok := response.Errors[nativeTopic]
	if !ok {
		return errors.New("kafka topic creation response omitted the topic")
	}
	if topicErr != nil && !errors.Is(topicErr, kafka.TopicAlreadyExists) {
		return topicErr
	}
	// An existing topic is never altered or reset. Verify its retained native
	// policy rather than trusting labels while broker configuration has drifted.
	configs, err := l.client.DescribeConfigs(ctx, &kafka.DescribeConfigsRequest{Resources: []kafka.DescribeConfigRequestResource{{ResourceType: kafka.ResourceTypeTopic, ResourceName: nativeTopic}}})
	if err != nil {
		return err
	}
	if len(configs.Resources) != 1 || configs.Resources[0].ResourceName != nativeTopic {
		return errors.New("kafka configuration response omitted the topic")
	}
	resource := configs.Resources[0]
	if resource.Error != nil {
		return resource.Error
	}
	for _, want := range topicConfiguration() {
		found := false
		for _, got := range resource.ConfigEntries {
			if got.ConfigName == want.ConfigName {
				if got.ConfigValue != want.ConfigValue {
					return fmt.Errorf("kafka retained topic has conflicting %s=%q", got.ConfigName, got.ConfigValue)
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("kafka retained topic omits configuration %s", want.ConfigName)
		}
	}
	if _, err := l.partitionCount(ctx); err != nil {
		return err
	}
	_, err = l.Bounds(ctx, 0)
	return err
}

func (l *nativeLog) partitionCount(ctx context.Context) (int32, error) {
	metadata, err := l.client.Metadata(ctx, &kafka.MetadataRequest{Topics: []string{nativeTopic}})
	if err != nil {
		return 0, err
	}
	if len(metadata.Brokers) == 0 {
		return 0, kafka.LeaderNotAvailable
	}
	if len(metadata.Brokers) != 1 || metadata.Brokers[0].ID != 1 {
		return 0, errors.New("kafka metadata differs from the owned single broker")
	}
	for _, topic := range metadata.Topics {
		if topic.Name != nativeTopic {
			continue
		}
		if topic.Error != nil {
			return 0, topic.Error
		}
		if len(topic.Partitions) == 0 {
			return 0, kafka.LeaderNotAvailable
		}
		for index, partition := range topic.Partitions {
			if partition.Error != nil {
				return 0, partition.Error
			}
			if partition.Leader.ID == 0 || partition.Leader.ID == -1 {
				return 0, kafka.LeaderNotAvailable
			}
			if partition.ID != index || partition.Leader.ID != 1 || len(partition.Replicas) != 1 || partition.Replicas[0].ID != 1 {
				return 0, errors.New("kafka topic has unexpected native partition layout")
			}
		}
		return int32(len(topic.Partitions)), nil
	}
	return 0, kafka.UnknownTopicOrPartition
}

func (l *nativeLog) EnsurePartitions(ctx context.Context, count int32) (err error) {
	ctx, finish := l.operation(ctx, "ensure partitions", &err)
	defer finish()
	if count < 1 {
		return errors.New("kafka partition count must be positive")
	}
	current, err := l.partitionCount(ctx)
	if err != nil || current >= count {
		return err
	}
	response, err := l.client.CreatePartitions(ctx, &kafka.CreatePartitionsRequest{Topics: []kafka.TopicPartitionsConfig{{Name: nativeTopic, Count: count}}})
	if err != nil {
		return err
	}
	creationErr, ok := response.Errors[nativeTopic]
	if !ok {
		return errors.New("kafka partition creation response omitted the topic")
	}
	// Another opener may have already grown the topic past this target. Verify
	// that native result instead of treating every InvalidPartitionNumber as success.
	if creationErr != nil && !errors.Is(creationErr, kafka.InvalidPartitionNumber) {
		return creationErr
	}
	for {
		current, err = l.partitionCount(ctx)
		if err == nil && current >= count {
			return nil
		}
		if err != nil && !errors.Is(err, kafka.LeaderNotAvailable) {
			return err
		}
		if waitErr := pause(ctx); waitErr != nil {
			return errors.Join(creationErr, err, waitErr)
		}
	}
}

// appendReader exposes the caller's records without copying their payloads or
// constructing a second slice of Kafka records. Kafka produces one atomic batch.
type appendReader struct {
	records []Record
	index   int
	current kafka.Record
}

func (r *appendReader) ReadRecord() (*kafka.Record, error) {
	if r.index == len(r.records) {
		return nil, io.EOF
	}
	record := &r.records[r.index]
	r.index++
	r.current = kafka.Record{Time: record.Timestamp, Key: kafka.NewBytes([]byte(record.PartitionKey)), Value: kafka.NewBytes(record.Data)}
	if record.Metadata != nil {
		r.current.Headers = []kafka.Header{{Key: "stackd.kinesis.metadata", Value: record.Metadata}}
	}
	return &r.current, nil
}

func (l *nativeLog) Append(ctx context.Context, partition int32, records []Record) (offset int64, err error) {
	ctx, finish := l.operation(ctx, "append", &err)
	defer finish()
	if partition < 0 || len(records) == 0 {
		return 0, errors.New("kafka append requires a partition and at least one record")
	}
	for _, record := range records {
		// kafka-go replaces a zero encoded timestamp with time.Now(). Refuse
		// that sentinel rather than silently changing the supplied timestamp.
		if record.Timestamp.UnixMilli() <= 0 {
			return 0, errors.New("kafka arrival timestamp must be after the Unix epoch")
		}
	}
	response, err := l.client.Produce(ctx, &kafka.ProduceRequest{Topic: nativeTopic, Partition: int(partition), RequiredAcks: kafka.RequireAll, Records: &appendReader{records: records}})
	if err != nil {
		return 0, err
	}
	if response.Error != nil {
		return 0, response.Error
	}
	for _, recordErr := range response.RecordErrors {
		err = errors.Join(err, recordErr)
	}
	if err != nil {
		return 0, err
	}
	if response.BaseOffset < 0 {
		return 0, errors.New("kafka append returned a negative base offset")
	}
	return response.BaseOffset, nil
}

func (l *nativeLog) offsets(ctx context.Context, partition int32, requests ...kafka.OffsetRequest) (kafka.PartitionOffsets, error) {
	if partition < 0 {
		return kafka.PartitionOffsets{}, errors.New("kafka partition must be nonnegative")
	}
	response, err := l.client.ListOffsets(ctx, &kafka.ListOffsetsRequest{Topics: map[string][]kafka.OffsetRequest{nativeTopic: requests}})
	if err != nil {
		return kafka.PartitionOffsets{}, err
	}
	for _, result := range response.Topics[nativeTopic] {
		if result.Partition == int(partition) {
			return result, result.Error
		}
	}
	return kafka.PartitionOffsets{}, errors.New("kafka offset response omitted the partition")
}

func (l *nativeLog) Bounds(ctx context.Context, partition int32) (bounds Bounds, err error) {
	ctx, finish := l.operation(ctx, "bounds", &err)
	defer finish()
	result, err := l.offsets(ctx, partition, kafka.FirstOffsetOf(int(partition)), kafka.LastOffsetOf(int(partition)))
	if err != nil {
		return Bounds{}, err
	}
	if result.FirstOffset < 0 || result.LastOffset < result.FirstOffset {
		return Bounds{}, errors.New("kafka returned invalid partition bounds")
	}
	return Bounds{Start: result.FirstOffset, End: result.LastOffset}, nil
}

func (l *nativeLog) OffsetAt(ctx context.Context, partition int32, at time.Time) (offset int64, err error) {
	ctx, finish := l.operation(ctx, "timestamp lookup", &err)
	defer finish()
	// Kafka stores CreateTime in milliseconds. Round a sub-millisecond query
	// upward so a record strictly before the requested instant is not returned.
	millis := at.UnixMilli()
	if at.Nanosecond()%int(time.Millisecond) != 0 {
		millis++
	}
	if millis < 0 {
		millis = 0
	}
	result, err := l.offsets(ctx, partition, kafka.OffsetRequest{Partition: int(partition), Timestamp: millis})
	if err != nil {
		return 0, err
	}
	for found := range result.Offsets {
		if found >= 0 {
			return found, nil
		}
		// No timestamp match: query the end after the lookup, rather than using
		// a cached end from before a concurrent append.
		bounds, err := l.Bounds(ctx, partition)
		return bounds.End, err
	}
	return 0, errors.New("kafka timestamp response omitted the offset")
}

func (l *nativeLog) Read(ctx context.Context, partition int32, offset int64, limit, maxBytes int) (result ReadResult, err error) {
	ctx, finish := l.operation(ctx, "read", &err)
	defer finish()
	if partition < 0 || offset < 0 || limit < 1 || maxBytes < 0 {
		return result, errors.New("kafka read requires nonnegative partition/offset/bytes and a positive record limit")
	}
	fetchBytes := min(max(int64(maxBytes), int64(nativeMaxBytes)), int64(math.MaxInt32))
	response, err := l.client.Fetch(ctx, &kafka.FetchRequest{Topic: nativeTopic, Partition: int(partition), Offset: offset, MinBytes: 0, MaxBytes: fetchBytes, MaxWait: time.Millisecond})
	if err != nil {
		return result, err
	}
	// RecordReader has no Close in kafka-go v0.4.49, despite FetchResponse's
	// stale comment. Drain every native record and close each byte reference,
	// including records outside the caller's limit or before the fetch offset.
	result.Bounds = Bounds{Start: response.LogStartOffset, End: response.HighWatermark}
	err = response.Error
	used, full := 0, false
	for {
		record, readErr := response.Records.ReadRecord()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			err = errors.Join(err, readErr)
			break
		}
		if err == nil {
			err = ctx.Err()
		}
		if err == nil && !full && record.Offset >= max(offset, result.Bounds.Start) {
			size := 0
			if record.Value != nil {
				size += record.Value.Len()
			}
			if record.Key != nil {
				size += record.Key.Len()
			}
			if len(result.Records) > 0 && (len(result.Records) >= limit || size > maxBytes-used) {
				full = true
			} else {
				var data, key []byte
				data, err = kafka.ReadAll(record.Value)
				if err == nil {
					key, err = kafka.ReadAll(record.Key)
				}
				if err == nil {
					var metadata []byte
					for _, header := range record.Headers {
						if header.Key == "stackd.kinesis.metadata" {
							metadata = bytes.Clone(header.Value)
							break
						}
					}
					result.Records = append(result.Records, Record{Offset: record.Offset, Timestamp: record.Time, PartitionKey: string(key), Data: data, Metadata: metadata})
					used += size
				}
			}
		}
		if record.Key != nil {
			err = errors.Join(err, record.Key.Close())
		}
		if record.Value != nil {
			err = errors.Join(err, record.Value.Close())
		}
	}
	return result, err
}
