package pipes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	dynamodbapi "stackd/internal/awsapi/dynamodbstreams"
	kinesisapi "stackd/internal/awsapi/kinesis"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
	"strconv"
	"strings"
	"time"
)

func (s *Service) acquire(ctx context.Context, p PipeRecord, work []Work, checkpoints []Checkpoint) error {
	if isKafka(p.Source.Kind) {
		return s.acquireKafka(ctx, p, work, checkpoints)
	}
	if p.Source.Kind == "sqs" {
		return s.acquireSQS(ctx, p, work)
	}
	var k lambda.KinesisConsumer
	var d lambda.DynamoDBConsumer
	var e *awswire.Error
	shards := []Checkpoint{}
	if p.Source.Kind == "kinesis" {
		k, e = s.sources.Kinesis(ctx, p)
		if e != nil {
			return s.delay(ctx, p, e.Error())
		}
		desc, e := k.Check(ctx)
		if e != nil {
			return s.delay(ctx, p, e.Error())
		}
		for {
			for _, v := range desc.Shards {
				shards = append(shards, Checkpoint{PipeID: p.ID, ShardID: value(v.ShardId), ParentID: value(v.ParentShardId), AdjacentParentID: value(v.AdjacentParentShardId)})
			}
			if desc.HasMoreShards == nil || !*desc.HasMoreShards || len(desc.Shards) == 0 {
				break
			}
			next, e := k.Describe(ctx, &kinesisapi.DescribeStreamInput{
				StreamARN:             new(kinesisapi.StreamARN(streamARN(p.SourceARN))),
				ExclusiveStartShardId: desc.Shards[len(desc.Shards)-1].ShardId,
			})
			if e != nil {
				return s.delay(ctx, p, e.Error())
			}
			desc = next.StreamDescription
		}
	} else {
		d, e = s.sources.DynamoDB(ctx, p)
		if e != nil {
			return s.delay(ctx, p, e.Error())
		}
		desc, e := d.Check(ctx)
		if e != nil {
			return s.delay(ctx, p, e.Error())
		}
		for {
			for _, v := range desc.Shards {
				shards = append(shards, Checkpoint{PipeID: p.ID, ShardID: value(v.ShardId), ParentID: value(v.ParentShardId)})
			}
			if value(desc.LastEvaluatedShardId) == "" {
				break
			}
			next, e := d.Describe(ctx, &dynamodbapi.DescribeStreamInput{StreamArn: new(dynamodbapi.StreamArn(p.SourceARN)), ExclusiveStartShardId: desc.LastEvaluatedShardId})
			if e != nil {
				return s.delay(ctx, p, e.Error())
			}
			desc = next.StreamDescription
		}
	}
	existing := map[string]Checkpoint{}
	for _, v := range checkpoints {
		existing[v.ShardID] = v
	}
	for _, v := range shards {
		if _, ok := existing[v.ShardID]; !ok {
			if p.Source.StartingPosition == "LATEST" {
				var sequence string
				if k != nil {
					sequence, e = k.LatestSequence(ctx, v.ShardID)
				} else {
					sequence, e = d.LatestSequence(ctx, v.ShardID)
				}
				if e != nil {
					return s.delay(ctx, p, e.Error())
				}
				v.Sequence = sequence
			}
			v.Initialized = true
			existing[v.ShardID] = v
		}
	}
	accepted := []Work{}
	ordinal := s.clock.Now().UnixNano()
	for _, w := range work {
		ordinal = max(ordinal, w.Ordinal+1)
	}
	for _, shard := range shards {
		cp := existing[shard.ShardID]
		if cp.Closed {
			continue
		}
		parentsReady := true
		for _, parent := range []string{cp.ParentID, cp.AdjacentParentID} {
			if parent == "" {
				continue
			}
			if parentCP, ok := existing[parent]; ok && !parentCP.Closed {
				parentsReady = false
			}
			for _, w := range work {
				if w.ShardID == parent {
					parentsReady = false
				}
			}
		}
		if !parentsReady {
			continue
		}
		pending := int32(0)
		last := cp.Sequence
		for _, w := range work {
			if w.ShardID == cp.ShardID {
				pending++
				last = w.Sequence
			}
		}
		capacity := p.Source.BatchSize * p.Source.Parallelism
		if pending >= capacity {
			continue
		}
		limit := min(int32(10000), capacity-pending)
		position := p.Source.StartingPosition
		if last != "" {
			position = "AFTER_SEQUENCE_NUMBER"
		} else if position == "LATEST" {
			position = "TRIM_HORIZON"
		}
		var records []Work
		if k != nil {
			records, cp, e = s.readKinesis(ctx, p, k, cp, last, position, limit)
		} else {
			records, cp, e = s.readDynamoDB(ctx, p, d, cp, last, position, limit)
		}
		if e != nil {
			if e.Code == "ExpiredIteratorException" {
				cp.Iterator = ""
				existing[cp.ShardID] = cp
				continue
			}
			return s.delay(ctx, p, e.Error())
		}
		existing[cp.ShardID] = cp
		for _, w := range records {
			w.ID = uuid.NewString()
			w.PipeID = p.ID
			w.ShardID = cp.ShardID
			w.Ordinal = ordinal
			ordinal++
			w.Phase = "ready"
			w.Due = s.clock.Now().Add(time.Duration(p.Source.WindowSeconds) * time.Second)
			matched, err := matches(p.Source.Filters, w.Event)
			if err != nil {
				return err
			}
			if !matched {
				w.Phase = "ack"
				w.Due = s.clock.Now()
			}
			if matched && p.Source.MaximumAge >= 0 && s.clock.Now().Sub(w.Created) >= time.Duration(p.Source.MaximumAge)*time.Second {
				w.Phase = "dlq"
				w.Due = s.clock.Now()
				w.LastError = "Record age exceeded"
			}
			accepted = append(accepted, w)
		}
	}
	cps := make([]Checkpoint, 0, len(existing))
	for _, v := range existing {
		cps = append(cps, v)
	}
	return s.retain(ctx, p, accepted, cps)
}
func streamARN(arn string) string {
	if i := strings.Index(arn, "/consumer/"); i >= 0 {
		return arn[:i]
	}
	return arn
}
func (s *Service) acquireSQS(ctx context.Context, p PipeRecord, work []Work) error {
	consumer, rejected := s.sources.SQS(ctx, p)
	if rejected != nil {
		return s.delay(ctx, p, rejected.Error())
	}
	count, size := int32(0), 0
	for _, w := range work {
		if w.Phase == "ready" {
			count++
			size += len(w.Event)
		}
	}
	if count >= p.Source.BatchSize || size >= 6*1024*1024 {
		return s.delay(ctx, p, "")
	}
	out, rejected := consumer.Receive(ctx, &sqsapi.ReceiveMessageInput{
		MaxNumberOfMessages:         new(sqsapi.NullableInteger(min(10, p.Source.BatchSize-count))),
		WaitTimeSeconds:             new(sqsapi.NullableInteger(0)),
		MessageSystemAttributeNames: sqsapi.MessageSystemAttributeList{"All"},
		MessageAttributeNames:       sqsapi.MessageAttributeNameList{"All"},
	})
	if rejected != nil {
		return s.delay(ctx, p, rejected.Error())
	}
	accepted := make([]Work, 0, len(out.Messages))
	ordinal := s.clock.Now().UnixNano()
	for _, w := range work {
		ordinal = max(ordinal, w.Ordinal+1)
	}
	for _, message := range out.Messages {
		event, err := sqsEvent(p, message)
		if err != nil {
			return err
		}
		created := s.clock.Now()
		if text := message.Attributes["SentTimestamp"]; text != "" {
			if n, err := strconv.ParseInt(string(text), 10, 64); err == nil {
				created = time.UnixMilli(n)
			}
		}
		w := Work{
			ID:       uuid.NewString(),
			PipeID:   p.ID,
			RecordID: value(message.MessageId),
			Receipt:  value(message.ReceiptHandle),
			GroupID:  string(message.Attributes["MessageGroupId"]),
			Event:    event,
			Ordinal:  ordinal,
			Created:  created,
			Due:      s.clock.Now().Add(time.Duration(p.Source.WindowSeconds) * time.Second),
			Phase:    "ready",
		}
		ordinal++
		for _, previous := range work {
			if previous.RecordID == w.RecordID {
				w.ID, w.Ordinal = previous.ID, previous.Ordinal
				break
			}
		}
		matched, err := matches(p.Source.Filters, event)
		if err != nil {
			return err
		}
		if !matched && w.Phase != "executing" {
			w.Phase, w.Due = "ack", s.clock.Now()
		}
		accepted = append(accepted, w)
	}
	return s.retain(ctx, p, accepted, nil)
}
func (s *Service) retain(ctx context.Context, p PipeRecord, work []Work, cps []Checkpoint) error {
	return s.repository.Update(ctx, func(t Transaction) error {
		current, err := t.PipeByID(p.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		retained, err := t.Work(p.ID)
		if err != nil {
			return err
		}
		if p.Source.Kind == "sqs" && stringsFIFO(p) {
			kept := retained[:0]
			for _, previous := range retained {
				successor, returned := false, false
				for _, received := range work {
					successor = successor || previous.GroupID != "" && received.GroupID == previous.GroupID
					returned = returned || received.RecordID == previous.RecordID
				}
				// FIFO cannot return a later message from this group while an
				// earlier queue message remains unavailable. Its absent waiting
				// receipt was redriven or deleted by the queue owner.
				if previous.Phase == "waiting" && successor && !returned {
					if err = t.DeleteWork(previous.ID); err != nil {
						return err
					}
					continue
				}
				kept = append(kept, previous)
			}
			retained = kept
		}
		known := make(map[string]int, len(retained))
		for index, v := range retained {
			known[v.ID] = index
		}
		for _, w := range work {
			index, exists := known[w.ID]
			if exists {
				previous := retained[index]
				if p.Source.Kind == "sqs" {
					// Receive runs outside this transaction. A target may have completed
					// meanwhile, so its current retry state, not the acquisition snapshot,
					// owns the next attempt and deadline.
					w.Attempts, w.LastError = previous.Attempts, previous.LastError
					w.Due = s.clock.Now()
					if w.LastError != "" && previous.Due.After(w.Due) {
						w.Due = previous.Due
					}
				}
				if previous.Phase == "ack" || previous.Phase == "executing" {
					// A concurrent target completion owns its result; only the fresh receipt
					// changes when visibility expired while that execution was in flight.
					previous.Receipt = w.Receipt
					w = previous
				}
				retained[index] = w
			} else {
				known[w.ID] = len(retained)
				retained = append(retained, w)
			}
			if err = t.PutWork(w); err != nil {
				return err
			}
		}
		for _, checkpoint := range cps {
			if err = t.PutCheckpoint(checkpoint); err != nil {
				return err
			}
		}
		if current.Version == p.Version {
			current.Due = workDue(current, retained, s.clock.Now())
			return t.PutPipe(current)
		}
		return nil
	})
}
func (s *Service) readKinesis(ctx context.Context, p PipeRecord, c lambda.KinesisConsumer, cp Checkpoint, last, position string, limit int32) ([]Work, Checkpoint, *awswire.Error) {
	if strings.Contains(p.SourceARN, "/consumer/") {
		return s.readKinesisSubscription(ctx, p, c, cp, last, position, limit)
	}
	if cp.Iterator == "" {
		in := &kinesisapi.GetShardIteratorInput{
			StreamARN:         new(kinesisapi.StreamARN(streamARN(p.SourceARN))),
			ShardId:           new(kinesisapi.ShardId(cp.ShardID)),
			ShardIteratorType: new(kinesisapi.ShardIteratorType(position)),
			Timestamp:         p.Source.StartingTime,
		}
		if last != "" {
			in.StartingSequenceNumber = new(kinesisapi.SequenceNumber(last))
		}
		out, e := c.Iterator(ctx, in)
		if e != nil {
			return nil, cp, e
		}
		cp.Iterator = value(out.ShardIterator)
	}
	out, e := c.Records(ctx, &kinesisapi.GetRecordsInput{
		StreamARN:     new(kinesisapi.StreamARN(streamARN(p.SourceARN))),
		ShardIterator: new(kinesisapi.ShardIterator(cp.Iterator)),
		Limit:         new(kinesisapi.GetRecordsInputLimit(limit)),
	})
	if e != nil {
		return nil, cp, e
	}
	cp.Iterator = value(out.NextShardIterator)
	cp.Closed = cp.Iterator == ""
	records, e := kinesisWork(p, cp.ShardID, out.Records, s.clock.Now())
	return records, cp, e
}
func (s *Service) readDynamoDB(ctx context.Context, p PipeRecord, c lambda.DynamoDBConsumer, cp Checkpoint, last, position string, limit int32) ([]Work, Checkpoint, *awswire.Error) {
	if cp.Iterator == "" {
		in := &dynamodbapi.GetShardIteratorInput{
			StreamArn:         new(dynamodbapi.StreamArn(p.SourceARN)),
			ShardId:           new(dynamodbapi.ShardId(cp.ShardID)),
			ShardIteratorType: new(dynamodbapi.ShardIteratorType(position)),
		}
		if last != "" {
			in.SequenceNumber = new(dynamodbapi.SequenceNumber(last))
		}
		out, e := c.Iterator(ctx, in)
		if e != nil {
			return nil, cp, e
		}
		cp.Iterator = value(out.ShardIterator)
	}
	out, e := c.Records(ctx, &dynamodbapi.GetRecordsInput{ShardIterator: new(dynamodbapi.ShardIterator(cp.Iterator)), Limit: new(dynamodbapi.PositiveIntegerObject(min(limit, 1000)))})
	if e != nil {
		return nil, cp, e
	}
	cp.Iterator = value(out.NextShardIterator)
	cp.Closed = cp.Iterator == ""
	records := make([]Work, 0, len(out.Records))
	for _, r := range out.Records {
		if r.Dynamodb == nil {
			continue
		}
		b, e := json.Marshal(r)
		if e != nil {
			return nil, cp, wireError(e)
		}
		var doc map[string]any
		if e = json.Unmarshal(b, &doc); e != nil {
			return nil, cp, wireError(e)
		}
		doc["eventSourceARN"] = p.SourceARN
		created := s.clock.Now()
		if r.Dynamodb.ApproximateCreationDateTime != nil {
			created = *r.Dynamodb.ApproximateCreationDateTime
			if nested, ok := doc["dynamodb"].(map[string]any); ok {
				nested["ApproximateCreationDateTime"] = float64(created.UnixMilli()) / 1000
			}
		}
		b, e = json.Marshal(doc)
		if e != nil {
			return nil, cp, wireError(e)
		}
		keys, err := json.Marshal(r.Dynamodb.Keys)
		if err != nil {
			return nil, cp, wireError(err)
		}
		records = append(records, Work{RecordID: value(r.EventID), Sequence: value(r.Dynamodb.SequenceNumber), GroupID: string(keys), Event: b, Created: created})
	}
	return records, cp, nil
}
func kinesisWork(p PipeRecord, shard string, records kinesisapi.RecordList, now time.Time) ([]Work, *awswire.Error) {
	out := make([]Work, 0, len(records))
	for _, r := range records {
		created := now
		if r.ApproximateArrivalTimestamp != nil {
			created = *r.ApproximateArrivalTimestamp
		}
		id := shard + ":" + value(r.SequenceNumber)
		b, e := json.Marshal(map[string]any{
			"kinesisSchemaVersion":        "1.0",
			"partitionKey":                value(r.PartitionKey),
			"sequenceNumber":              value(r.SequenceNumber),
			"data":                        base64.StdEncoding.EncodeToString(r.Data),
			"approximateArrivalTimestamp": float64(created.UnixMilli()) / 1000,
			"eventSource":                 "aws:kinesis",
			"eventVersion":                "1.0",
			"eventID":                     id,
			"eventName":                   "aws:kinesis:record",
			"invokeIdentityArn":           p.RoleARN,
			"awsRegion":                   p.Key.Region,
			"eventSourceARN":              p.SourceARN,
		})
		if e != nil {
			return nil, wireError(e)
		}
		out = append(out, Work{RecordID: id, Sequence: value(r.SequenceNumber), GroupID: value(r.PartitionKey), Event: b, Created: created})
	}
	return out, nil
}
func sqsEvent(p PipeRecord, m sqsapi.Message) ([]byte, error) {
	attributes := map[string]any{}
	for k, v := range m.MessageAttributes {
		a := map[string]any{"dataType": value(v.DataType), "stringListValues": []string{}, "binaryListValues": [][]byte{}}
		if v.StringValue != nil {
			a["stringValue"] = value(v.StringValue)
		}
		if v.BinaryValue != nil {
			a["binaryValue"] = v.BinaryValue
		}
		if v.StringListValues != nil {
			a["stringListValues"] = v.StringListValues
		}
		if v.BinaryListValues != nil {
			a["binaryListValues"] = v.BinaryListValues
		}
		attributes[string(k)] = a
	}
	return json.Marshal(map[string]any{
		"messageId":         value(m.MessageId),
		"receiptHandle":     value(m.ReceiptHandle),
		"body":              value(m.Body),
		"attributes":        m.Attributes,
		"messageAttributes": attributes,
		"md5OfBody":         value(m.MD5OfBody),
		"eventSource":       "aws:sqs",
		"eventSourceARN":    p.SourceARN,
		"awsRegion":         p.Key.Region,
	})
}
