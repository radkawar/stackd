package kinesis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	engine "stackd/engine/kinesis"
	api "stackd/internal/awsapi/kinesis"
)

func registerConsumers(s *Service) {
	registerControl(s, "RegisterStreamConsumer", s.registerStreamConsumer)
	registerControl(s, "DescribeStreamConsumer", s.describeStreamConsumer)
	registerControl(s, "ListStreamConsumers", s.listStreamConsumers)
	registerControl(s, "DeregisterStreamConsumer", s.deregisterStreamConsumer)
	registerOperation(s, "SubscribeToShard", s.SubscribeToShard)
}

func consumerSummary(record ConsumerRecord) api.Consumer {
	return api.Consumer{ConsumerARN: record.Data.ConsumerARN, ConsumerCreationTimestamp: record.Data.ConsumerCreationTimestamp, ConsumerName: record.Data.ConsumerName, ConsumerStatus: record.Data.ConsumerStatus}
}

func consumerMissing(key ConsumerKey) error {
	return failure("ResourceNotFoundException", fmt.Sprintf("Consumer %s under stream: %s, account %s not found.", key.Name, key.Stream.Name, key.Stream.AccountID))
}

// ARN selectors authorize the exact consumer, including its resource policy and
// tags. The older stream/name selectors use the distinct stream permission.
func (s *Service) consumer(ctx context.Context, r Reader, name, resource, streamARN, action string) (ConsumerRecord, error) {
	if resource != "" {
		key, err := consumerKey(ctx, resource)
		if err != nil {
			return ConsumerRecord{}, err
		}
		if name != "" && name != key.Name || streamARN != "" && streamARN != key.Stream.ARN() {
			return ConsumerRecord{}, failure("InvalidArgumentException", "ConsumerARN, ConsumerName and StreamARN must identify the same consumer.")
		}
		if err = s.authorizeResource(ctx, r, ResourceKey{Scope: key.Stream.Scope, ARN: key.ARN()}, nil, action); err != nil {
			return ConsumerRecord{}, err
		}
		record, err := r.Consumer(key)
		if errors.Is(err, ErrNotFound) {
			err = consumerMissing(key)
		}
		if err == nil {
			rememberResource(ctx, action, ResourceKey{Scope: record.Key.Stream.Scope, ARN: record.Key.ARN()})
		}
		return record, err
	}
	if name == "" || streamARN == "" {
		return ConsumerRecord{}, failure("InvalidArgumentException", "Specify ConsumerARN or both StreamARN and ConsumerName.")
	}
	if !streamNamePattern.MatchString(name) {
		return ConsumerRecord{}, failure("ValidationException", "Invalid consumer name")
	}
	stream, err := s.stream(ctx, r, "", streamARN, action)
	if err != nil {
		return ConsumerRecord{}, err
	}
	records, err := r.Consumers(stream.Key)
	if err != nil {
		return ConsumerRecord{}, err
	}
	for _, record := range records {
		if record.Key.Name == name {
			if err := checkResourceOwner(ctx, r, ResourceKey{Scope: record.Key.Stream.Scope, ARN: record.Key.ARN()}, action); err != nil {
				return ConsumerRecord{}, err
			}
			rememberResource(ctx, action, ResourceKey{Scope: record.Key.Stream.Scope, ARN: record.Key.ARN()})
			return record, nil
		}
	}
	return ConsumerRecord{}, consumerMissing(ConsumerKey{Stream: stream.Key, Name: name})
}

func (s *Service) registerStreamConsumer(ctx context.Context, tx Transaction, in *api.RegisterStreamConsumerInput) (*api.RegisterStreamConsumerOutput, error) {
	claim, err := resourceOwnerFor(ctx)
	if err != nil {
		return nil, err
	}
	name := value(in.ConsumerName)
	if !streamNamePattern.MatchString(name) {
		return nil, failure("ValidationException", "Invalid consumer name")
	}
	key, err := streamKey(ctx, "", value(in.StreamARN))
	if err != nil {
		return nil, err
	}
	conditions := requestTagConditions(in.Tags)
	if err = s.authorizeResource(ctx, tx, ResourceKey{Scope: key.Scope, ARN: key.ARN()}, conditions, "RegisterStreamConsumer"); err != nil {
		return nil, err
	}
	stream, err := tx.Stream(key)
	if err != nil {
		return nil, err
	}
	if err = requireActive(stream); err != nil {
		return nil, err
	}
	// Consumers become ACTIVE only through native stream reconciliation.
	if err = s.requireRuntime(); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	consumerKey := ConsumerKey{Stream: key, Name: name, CreatedAt: now.Unix()}
	resourceKey := ResourceKey{Scope: key.Scope, ARN: consumerKey.ARN()}
	if in.Tags != nil {
		if len(in.Tags) > 0 {
			if err = validateTags(in.Tags); err != nil {
				return nil, err
			}
		}
		if err = s.authorizeResource(ctx, tx, resourceKey, requestTagConditions(in.Tags), "TagResource"); err != nil {
			return nil, err
		}
	}
	records, err := tx.Consumers(key)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.Key.Name == name {
			return nil, failure("ResourceInUseException", "Consumer "+name+" already exists for stream "+key.Name+".")
		}
	}
	limit := 20
	if streamMode(stream) == api.StreamModeON_DEMAND {
		account, err := accountSettings(tx, key.Scope, now)
		if err != nil {
			return nil, err
		}
		if value(account.Commitment.Status) != "DISABLED" {
			limit = 50
		}
	}
	if len(records) >= limit {
		return nil, failure("LimitExceededException", fmt.Sprintf("Stream %s already has the maximum of %d registered consumers.", key.Name, limit))
	}
	creating := 0
	for _, record := range records {
		if value(record.Data.ConsumerStatus) == "CREATING" {
			creating++
		}
	}
	if creating >= 5 {
		return nil, failure("LimitExceededException", "Only five consumers can be in the CREATING state at the same time.")
	}
	record := ConsumerRecord{Key: consumerKey, Owner: claim.Owner, Data: api.ConsumerDescription{ConsumerARN: new(api.ConsumerARN(consumerKey.ARN())), ConsumerName: new(api.ConsumerName(name)), ConsumerCreationTimestamp: &now, ConsumerStatus: new(api.ConsumerStatusCREATING), StreamARN: stream.Data.StreamARN}}
	if err = tx.PutConsumer(record); err != nil {
		return nil, err
	}
	if len(in.Tags) > 0 {
		if err = tx.PutTags(TagRecord{Key: resourceKey, Tags: sortedTags(in.Tags)}); err != nil {
			return nil, err
		}
	}
	stream.Data.ConsumerCount = new(api.ConsumerCountObject(len(records) + 1))
	if err = tx.PutStream(stream); err != nil {
		return nil, err
	}
	consumer := consumerSummary(record)
	return &api.RegisterStreamConsumerOutput{Consumer: &consumer}, nil
}

func (s *Service) describeStreamConsumer(ctx context.Context, tx Transaction, in *api.DescribeStreamConsumerInput) (*api.DescribeStreamConsumerOutput, error) {
	record, err := s.consumer(ctx, tx, value(in.ConsumerName), value(in.ConsumerARN), value(in.StreamARN), "DescribeStreamConsumer")
	if err != nil {
		return nil, err
	}
	return &api.DescribeStreamConsumerOutput{ConsumerDescription: &record.Data}, nil
}

func (s *Service) deregisterStreamConsumer(ctx context.Context, tx Transaction, in *api.DeregisterStreamConsumerInput) (*api.DeregisterStreamConsumerOutput, error) {
	record, err := s.consumer(ctx, tx, value(in.ConsumerName), value(in.ConsumerARN), value(in.StreamARN), "DeregisterStreamConsumer")
	if err != nil {
		return nil, err
	}
	if value(record.Data.ConsumerStatus) != "DELETING" {
		if err = s.requireRuntime(); err != nil {
			return nil, err
		}
		record.Data.ConsumerStatus = new(api.ConsumerStatusDELETING)
		record.DeleteAt = s.clock.Now().Add(lifecycleDelay)
		if err = tx.PutConsumer(record); err != nil {
			return nil, err
		}
	}
	return &api.DeregisterStreamConsumerOutput{}, nil
}

func (s *Service) listStreamConsumers(ctx context.Context, tx Transaction, in *api.ListStreamConsumersInput) (*api.ListStreamConsumersOutput, error) {
	if in.NextToken != nil && in.StreamCreationTimestamp != nil {
		return nil, failure("InvalidArgumentException", "StreamCreationTimestamp cannot be specified with NextToken.")
	}
	stream, err := s.stream(ctx, tx, "", value(in.StreamARN), "ListStreamConsumers")
	if err != nil {
		return nil, err
	}
	if err = requireReadable(stream); err != nil {
		return nil, err
	}
	if in.StreamCreationTimestamp != nil && (stream.Data.StreamCreationTimestamp == nil || !in.StreamCreationTimestamp.Equal(*stream.Data.StreamCreationTimestamp)) {
		return nil, failure("ResourceNotFoundException", "No stream exists with the specified creation timestamp.")
	}
	limit := 100
	if in.MaxResults != nil {
		if *in.MaxResults < 1 || *in.MaxResults > 10000 {
			return nil, failure("ValidationException", "MaxResults must be between 1 and 10000")
		}
		limit = min(100, int(*in.MaxResults))
	}
	// The timestamp filter is an identity filter, so the resolved incarnation
	// binds it even when a subsequent request supplies only NextToken.
	collection := fmt.Sprintf("consumers:%s:%s:%s:%s:%s", scopeFor(ctx).Partition, scopeFor(ctx).AccountID, scopeFor(ctx).Region, stream.Key.ARN(), stream.EngineID)
	after, err := decodeCursor(in.NextToken, collection, s.clock.Now())
	if err != nil {
		return nil, err
	}
	records, err := tx.Consumers(stream.Key)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(records, func(a, b ConsumerRecord) int { return strings.Compare(a.Key.ARN(), b.Key.ARN()) })
	out := &api.ListStreamConsumersOutput{Consumers: api.ConsumerList{}}
	for _, record := range records {
		if record.Key.ARN() <= after {
			continue
		}
		if len(out.Consumers) == limit {
			out.NextToken = encodeCursor(collection, value(out.Consumers[len(out.Consumers)-1].ConsumerARN), s.clock.Now())
			break
		}
		out.Consumers = append(out.Consumers, consumerSummary(record))
	}
	return out, nil
}

// reconcileConsumers runs under the native stream gate, never with a repository
// transaction held while probing Kafka. State and public counts commit together.
func (s *Service) reconcileConsumers(ctx context.Context, stream StreamRecord, log engine.Log) (time.Time, error) {
	var records []ConsumerRecord
	var shards []ShardRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		records, err = r.Consumers(stream.Key)
		if err != nil {
			return err
		}
		shards, err = r.Shards(stream.Key)
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	now := s.clock.Now()
	var next time.Time
	activate := false
	for _, record := range records {
		switch value(record.Data.ConsumerStatus) {
		case "CREATING":
			at := record.Data.ConsumerCreationTimestamp.Add(lifecycleDelay)
			if now.Before(at) {
				next = earlierDeadline(next, at)
			} else {
				activate = true
			}
		case "DELETING":
			if now.Before(record.DeleteAt) {
				next = earlierDeadline(next, record.DeleteAt)
			}
		}
	}
	var readinessErr error
	if activate {
		readinessErr = requireReadable(stream)
		if readinessErr == nil && log == nil {
			readinessErr = errors.New("kinesis consumer activation requires a native log")
		}
		ready := false
		if readinessErr == nil {
			for _, shard := range shards {
				if shard.State != ShardOpen {
					continue
				}
				if _, readinessErr = log.Bounds(ctx, shard.Key.Partition); readinessErr != nil {
					break
				}
				ready = true
			}
		}
		if readinessErr == nil && !ready {
			readinessErr = errors.New("kinesis consumer activation requires a ready native shard")
		}
		activate = readinessErr == nil
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Stream(stream.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.EngineID != stream.EngineID {
			return nil
		}
		consumers, err := tx.Consumers(stream.Key)
		if err != nil {
			return err
		}
		count := len(consumers)
		for _, record := range consumers {
			switch value(record.Data.ConsumerStatus) {
			case "CREATING":
				at := record.Data.ConsumerCreationTimestamp.Add(lifecycleDelay)
				if now.Before(at) {
					next = earlierDeadline(next, at)
					continue
				}
				if !activate {
					continue
				}
				record.Data.ConsumerStatus = new(api.ConsumerStatusACTIVE)
				if err = tx.PutConsumer(record); err != nil {
					return err
				}
			case "DELETING":
				if now.Before(record.DeleteAt) {
					next = earlierDeadline(next, record.DeleteAt)
					continue
				}
				// Deregistration prevents new admissions, not already admitted reads.
				if err = tx.DeleteConsumer(record.Key); err != nil {
					return err
				}
				count--
			}
		}
		if current.Data.ConsumerCount == nil || int(*current.Data.ConsumerCount) != count {
			current.Data.ConsumerCount = new(api.ConsumerCountObject(count))
			return tx.PutStream(current)
		}
		return nil
	})
	return next, errors.Join(err, readinessErr)
}
