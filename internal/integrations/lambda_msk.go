package integrations

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"

	"stackd/internal/services/lambda"
	"stackd/internal/services/pipes"
)

// LambdaKafka shares the native Kafka coordinator, fetch and incarnation fences
// with Pipes, but assumes only the current Lambda function execution role.
type LambdaKafka struct {
	Roles    ServiceRoles
	Clusters PipesKafkaClusters
	Secrets  PipesKafkaSecrets
	Networks lambda.SourceNetworks
}

func (a *LambdaKafka) Open(ctx context.Context, function lambda.FunctionKey, role string, mapping lambda.EventSourceMappingRecord) (lambda.KafkaConsumer, error) {
	session, wire := openLambdaSourceSession(ctx, a.Roles, function, role)
	if wire != nil {
		return nil, wire
	}
	d := mapping.Settings.Kafka
	if d == nil {
		return nil, errors.New("kafka mapping configuration is required")
	}
	source := kafkaMemberConfig{topic: d.Topic, groupID: d.ConsumerGroupID, clientID: "stackd-lambda-" + mapping.Key.UUID, startingPosition: d.StartingPosition, startingTimestamp: d.StartingPositionTimestamp}
	var network lambda.SourceNetworkLease
	if len(d.Network.SubnetIDs) != 0 {
		if a.Networks == nil {
			return nil, errors.New("kafka VPC sources require native source networking")
		}
		var err error
		network, err = a.Networks.Open(ctx, function, role, mapping.Key.ARN(), d.Network)
		if err != nil {
			return nil, err
		}
		source.dial = network.DialContext
	}
	consumer := &pipesKafkaConsumer{source: source, identity: pipes.KafkaIdentity{ClusterID: d.Identity.ClusterID, TopicID: d.Identity.TopicID}}
	consumer.resolve = func(ctx context.Context) (pipesKafkaAccess, error) {
		if network != nil {
			if err := network.Check(ctx); err != nil {
				return pipesKafkaAccess{}, err
			}
		}
		ctx, wire := session.context(ctx)
		if wire != nil {
			return pipesKafkaAccess{}, wire
		}
		return a.access(ctx, mapping)
	}
	return &lambdaKafkaConsumer{native: consumer, network: network}, nil
}

type lambdaKafkaConsumer struct {
	native  *pipesKafkaConsumer
	network lambda.SourceNetworkLease
}

func (c *lambdaKafkaConsumer) Check(ctx context.Context) error {
	access, err := c.native.resolve(ctx)
	if err != nil {
		return err
	}
	_, _, err = access.security()
	return err
}

func (c *lambdaKafkaConsumer) Identity(ctx context.Context) (lambda.KafkaIdentity, error) {
	v, err := c.native.Identity(ctx)
	return lambda.KafkaIdentity{ClusterID: v.ClusterID, TopicID: v.TopicID}, err
}
func (c *lambdaKafkaConsumer) BootstrapServers(ctx context.Context) (string, error) {
	if _, err := c.native.current(ctx); err != nil {
		return "", err
	}
	c.native.mu.Lock()
	defer c.native.mu.Unlock()
	return strings.Join(c.native.access.brokers, ","), nil
}
func (c *lambdaKafkaConsumer) Assignments(ctx context.Context) ([]lambda.KafkaPartition, error) {
	member, err := c.native.current(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := member.assignments(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	requests := make([]kafka.OffsetRequest, len(rows))
	for i, v := range rows {
		requests[i] = kafka.FirstOffsetOf(v.ID)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	bounds, err := member.client.ListOffsets(ctx, &kafka.ListOffsetsRequest{Topics: map[string][]kafka.OffsetRequest{member.topic: requests}, IsolationLevel: kafka.ReadCommitted})
	if err != nil {
		return nil, err
	}
	first := make(map[int]int64, len(rows))
	for _, v := range bounds.Topics[member.topic] {
		if v.Error != nil {
			return nil, v.Error
		}
		first[v.Partition] = v.FirstOffset
	}
	out := make([]lambda.KafkaPartition, len(rows))
	for i, v := range rows {
		earliest, ok := first[v.ID]
		if !ok || earliest < 0 {
			return nil, errors.New("kafka source omitted the partition log start")
		}
		out[i] = lambda.KafkaPartition{ID: v.ID, Offset: v.Offset, FirstOffset: earliest, Committed: v.Committed}
	}
	c.native.mu.Lock()
	defer c.native.mu.Unlock()
	if err := c.native.checkIdentity(ctx, member); err != nil {
		return nil, err
	}
	return out, nil
}
func (c *lambdaKafkaConsumer) Fetch(ctx context.Context, partition int, offset int64, limit int) (lambda.KafkaPage, error) {
	page, err := c.native.Fetch(ctx, partition, offset, limit)
	if err != nil {
		return lambda.KafkaPage{}, err
	}
	out := lambda.KafkaPage{NextOffset: page.NextOffset, Records: make([]lambda.KafkaRecord, len(page.Records))}
	for i, v := range page.Records {
		record := lambda.KafkaRecord{Partition: v.Partition, Offset: v.Offset, Timestamp: v.Timestamp, TimestampType: v.TimestampType, Key: v.Key, Value: v.Value, Headers: make([]lambda.KafkaHeader, len(v.Headers))}
		for j, h := range v.Headers {
			record.Headers[j] = lambda.KafkaHeader{Key: h.Key, Value: h.Value}
		}
		out.Records[i] = record
	}
	return out, nil
}
func (c *lambdaKafkaConsumer) Commit(ctx context.Context, offsets map[int]int64) error {
	return c.native.Commit(ctx, offsets)
}
func (c *lambdaKafkaConsumer) Lease(ctx context.Context, partition int) (context.Context, context.CancelFunc, error) {
	return c.native.Lease(ctx, partition)
}
func (c *lambdaKafkaConsumer) Close() error {
	err := c.native.Close()
	if c.network != nil {
		err = errors.Join(err, c.network.Close())
	}
	return err
}
