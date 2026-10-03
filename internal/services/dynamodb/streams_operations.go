package dynamodb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/dynamodbstreams"
	"strings"
	"time"
)

func streamKey(ctx context.Context, resource string) (PolicyKey, error) {
	a, err := arn.Parse(resource)
	scope := scopeFor(ctx)
	if err != nil || a.Service != "dynamodb" || a.Partition != scope.Partition || a.Region != scope.Region || a.AccountID == "" || !strings.HasPrefix(a.Resource, "table/") {
		return PolicyKey{}, failure("ValidationException", "Invalid stream ARN.")
	}
	parts := strings.Split(a.Resource, "/")
	if len(parts) != 4 || parts[1] == "" || parts[2] != "stream" || parts[3] == "" {
		return PolicyKey{}, failure("ValidationException", "Invalid stream ARN.")
	}
	return PolicyKey{Scope: Scope{a.Partition, a.AccountID, a.Region}, ResourceARN: resource}, nil
}
func (p *Streams) authorize(ctx context.Context, r Reader, g StreamGeneration, actions ...string) error {
	bound, err := r.Policy(g.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	conditions := map[string][]string{}
	tags, err := r.Tags(g.Table)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	for _, tag := range tags.Tags {
		conditions["aws:ResourceTag/"+value(tag.Key)] = []string{value(tag.Value)}
	}
	now := p.s.clock.Now()
	request := authorization.Request{ResourceARN: g.Key.ResourceARN, Context: conditions, EvaluationTime: &now}
	if bound.Policy.Document != "" {
		request.ResourcePolicies = []authorization.BoundPolicy{bound.Policy}
	}
	for _, action := range actions {
		permission := request
		permission.Action = "dynamodb:" + action
		if rejected := p.s.authorizer.Authorize(ctx, permission); rejected != nil {
			return rejected
		}
	}
	return nil
}
func (p *Streams) resolve(ctx context.Context, resource string, actions ...string) (StreamGeneration, error) {
	key, err := streamKey(ctx, resource)
	if err != nil {
		return StreamGeneration{}, err
	}
	var g StreamGeneration
	err = p.s.repository.View(ctx, func(r Reader) error {
		var err error
		g, err = r.Stream(key)
		if err != nil {
			return err
		}
		if streamExpired(g, p.s.clock.Now()) {
			return ErrNotFound
		}
		return p.authorize(r.Context(), r, g, actions...)
	})
	return g, err
}
func (p *Streams) refresh(ctx context.Context, g StreamGeneration) error {
	release, err := p.s.engines.lockData(ctx, g.DatabaseID)
	if err != nil {
		return err
	}
	defer release()
	return p.s.ingestStream(ctx, g)
}
func streamLimit(in *api.PositiveIntegerObject, maximum int) (int, error) {
	if in == nil {
		return maximum, nil
	}
	if *in < 1 || int(*in) > maximum {
		return 0, failure("ValidationException", "Limit is outside the supported range.")
	}
	return int(*in), nil
}
func (p *Streams) list(ctx context.Context, in *api.ListStreamsInput) (*api.ListStreamsOutput, error) {
	limit, err := streamLimit(in.Limit, 100)
	if err != nil {
		return nil, err
	}
	if err := p.s.authorize(ctx, "ListStreams", "*", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	after := value(in.ExclusiveStartStreamArn)
	if after != "" {
		key, err := streamKey(ctx, after)
		if err != nil {
			return nil, err
		}
		if key.Scope != scope {
			return nil, failure("ValidationException", "ExclusiveStartStreamArn is outside the requested scope.")
		}
	}
	out := &api.ListStreamsOutput{Streams: api.StreamList{}}
	err = p.s.repository.View(ctx, func(r Reader) error {
		generations, err := r.Streams()
		if err != nil {
			return err
		}
		for _, g := range generations {
			if g.Key.Scope != scope || streamExpired(g, p.s.clock.Now()) || g.Key.ResourceARN <= after || value(in.TableName) != "" && g.Table.Name != value(in.TableName) {
				continue
			}
			if len(out.Streams) == limit {
				out.LastEvaluatedStreamArn = out.Streams[len(out.Streams)-1].StreamArn
				break
			}
			out.Streams = append(out.Streams, api.Stream{StreamArn: new(api.StreamArn(g.Key.ResourceARN)), StreamLabel: new(api.String(g.Label)), TableName: new(api.TableName(g.Table.Name))})
		}
		return nil
	})
	return out, err
}
func shardDescription(sh StreamShard) api.Shard {
	out := api.Shard{ShardId: new(api.ShardId(sh.ID)), SequenceNumberRange: &api.SequenceNumberRange{}}
	if sh.ParentID != "" {
		out.ParentShardId = new(api.ShardId(sh.ParentID))
	}
	if sh.Start != "" {
		out.SequenceNumberRange.StartingSequenceNumber = new(api.SequenceNumber(sh.Start))
	}
	if sh.End != "" {
		out.SequenceNumberRange.EndingSequenceNumber = new(api.SequenceNumber(sh.End))
	}
	return out
}
func (p *Streams) describe(ctx context.Context, in *api.DescribeStreamInput) (*api.DescribeStreamOutput, error) {
	limit, err := streamLimit(in.Limit, 100)
	if err != nil {
		return nil, err
	}
	g, err := p.resolve(ctx, value(in.StreamArn), "DescribeStream")
	if err != nil {
		return nil, err
	}
	if in.ShardFilter != nil && (value(in.ShardFilter.Type) != "CHILD_SHARDS" || value(in.ShardFilter.ShardId) == "" || in.ExclusiveStartShardId != nil) {
		return nil, failure("ValidationException", "ShardFilter requires CHILD_SHARDS and ShardId, without ExclusiveStartShardId.")
	}
	return p.describeGeneration(ctx, g, in, limit)
}

func (p *Streams) describeGeneration(ctx context.Context, g StreamGeneration, in *api.DescribeStreamInput, limit int) (*api.DescribeStreamOutput, error) {
	if err := p.refresh(ctx, g); err != nil {
		return nil, err
	}
	status := api.StreamStatusENABLED
	if !g.ClosedAt.IsZero() {
		status = api.StreamStatusDISABLED
	}
	d := &api.StreamDescription{StreamArn: new(api.StreamArn(g.Key.ResourceARN)), StreamLabel: new(api.String(g.Label)), TableName: new(api.TableName(g.Table.Name)), CreationRequestDateTime: &g.CreatedAt, StreamStatus: &status, StreamViewType: &g.ViewType, KeySchema: g.KeySchema, Shards: api.ShardDescriptionList{}}
	err := p.s.repository.View(ctx, func(r Reader) error {
		if streamExpired(g, p.s.clock.Now()) {
			return ErrNotFound
		}
		shards, err := r.StreamShards(g.Key.ResourceARN)
		if err != nil {
			return err
		}
		for _, sh := range shards {
			if sh.ID <= value(in.ExclusiveStartShardId) || in.ShardFilter != nil && sh.ParentID != value(in.ShardFilter.ShardId) {
				continue
			}
			if len(d.Shards) == limit {
				d.LastEvaluatedShardId = d.Shards[len(d.Shards)-1].ShardId
				break
			}
			d.Shards = append(d.Shards, shardDescription(sh))
		}
		return nil
	})
	return &api.DescribeStreamOutput{StreamDescription: d}, err
}
func getStreamShard(r Reader, resource, id string) (StreamShard, error) {
	shards, err := r.StreamShards(resource)
	if err != nil {
		return StreamShard{}, err
	}
	for _, sh := range shards {
		if sh.ID == id {
			return sh, nil
		}
	}
	return StreamShard{}, ErrNotFound
}

// Like the other service pagination cursors, iterators carry their position
// rather than creating durable state on every empty poll. IAM is checked anew
// when the stream is resolved; an iterator is not an authorization capability.
type streamIterator struct {
	Scope     Scope     `json:"scope"`
	StreamARN string    `json:"arn"`
	ShardID   string    `json:"shard"`
	Position  string    `json:"position"`
	Inclusive bool      `json:"inclusive,omitempty"`
	ExpiresAt time.Time `json:"expires"`
}

func newStreamIterator(ctx context.Context, g StreamGeneration, sh StreamShard, pos string, inclusive bool, now time.Time) (*api.ShardIterator, error) {
	it := streamIterator{Scope: scopeFor(ctx), StreamARN: g.Key.ResourceARN, ShardID: sh.ID, Position: pos, Inclusive: inclusive, ExpiresAt: now.Add(15 * time.Minute)}
	data, err := json.Marshal(it)
	if err != nil {
		return nil, err
	}
	return new(api.ShardIterator(base64.RawURLEncoding.EncodeToString(data))), nil
}

func decodeStreamIterator(token string) (streamIterator, error) {
	var it streamIterator
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || json.Unmarshal(data, &it) != nil || it.StreamARN == "" || it.ShardID == "" || it.ExpiresAt.IsZero() {
		return it, failure("ValidationException", "Invalid shard iterator.")
	}
	for _, c := range it.Position {
		if c < '0' || c > '9' {
			return it, failure("ValidationException", "Invalid shard iterator.")
		}
	}
	return it, nil
}
func trimmed() error {
	return failure("TrimmedDataAccessException", "The data you are trying to access has been trimmed.")
}
func (p *Streams) iterator(ctx context.Context, in *api.GetShardIteratorInput) (*api.GetShardIteratorOutput, error) {
	kind := value(in.ShardIteratorType)
	sequence := value(in.SequenceNumber)
	switch kind {
	case "AT_SEQUENCE_NUMBER", "AFTER_SEQUENCE_NUMBER":
		if sequence == "" {
			return nil, failure("ValidationException", "SequenceNumber is required for this iterator type.")
		}
		for _, c := range sequence {
			if c < '0' || c > '9' {
				return nil, failure("ValidationException", "Invalid sequence number.")
			}
		}
	case "TRIM_HORIZON", "LATEST":
		if sequence != "" {
			return nil, failure("ValidationException", "SequenceNumber is not valid for this iterator type.")
		}
	default:
		return nil, failure("ValidationException", "Invalid ShardIteratorType.")
	}
	g, err := p.resolve(ctx, value(in.StreamArn), "GetShardIterator")
	if err != nil {
		return nil, err
	}
	if err := p.refresh(ctx, g); err != nil {
		return nil, err
	}
	out := &api.GetShardIteratorOutput{}
	err = p.s.repository.Update(ctx, func(tx Transaction) error {
		now := p.s.clock.Now()
		if streamExpired(g, now) {
			return ErrNotFound
		}
		if _, err := tx.TrimStreamEntries(g.Key.ResourceARN, now.Add(-24*time.Hour)); err != nil {
			return err
		}
		sh, err := getStreamShard(tx, g.Key.ResourceARN, value(in.ShardId))
		if err != nil {
			return err
		}
		point := sh.TrimmedThrough
		inclusive := kind == "AT_SEQUENCE_NUMBER"
		switch kind {
		case "LATEST":
			sequence = sh.Checkpoint
		case "TRIM_HORIZON":
			sequence = point
		default:
			if point != "" && (compareSequence(sequence, point) < 0 || inclusive && compareSequence(sequence, point) == 0) {
				return trimmed()
			}
		}
		out.ShardIterator, err = newStreamIterator(ctx, g, sh, sequence, inclusive, now)
		if err != nil {
			return err
		}
		return nil
	})
	return out, err
}
func (p *Streams) records(ctx context.Context, in *api.GetRecordsInput) (*api.GetRecordsOutput, error) {
	limit := 1000
	if in.Limit != nil {
		if *in.Limit > 1000 {
			return nil, failure("LimitExceededException", "GetRecords limit must not exceed 1000.")
		}
		if *in.Limit < 1 {
			return nil, failure("ValidationException", "Limit must be positive.")
		}
		limit = int(*in.Limit)
	}
	it, err := decodeStreamIterator(value(in.ShardIterator))
	if err != nil {
		return nil, err
	}
	if it.Scope != scopeFor(ctx) {
		return nil, failure("ValidationException", "Invalid shard iterator scope.")
	}
	if !p.s.clock.Now().Before(it.ExpiresAt) {
		return nil, failure("ExpiredIteratorException", "The provided iterator exceeds the maximum age allowed.")
	}
	g, err := p.resolve(ctx, it.StreamARN, "GetRecords")
	if err != nil {
		return nil, err
	}
	if err := p.refresh(ctx, g); err != nil {
		return nil, err
	}
	out := &api.GetRecordsOutput{Records: api.RecordList{}}
	err = p.s.repository.Update(ctx, func(tx Transaction) error {
		now := p.s.clock.Now()
		if !now.Before(it.ExpiresAt) {
			return failure("ExpiredIteratorException", "The provided iterator exceeds the maximum age allowed.")
		}
		if streamExpired(g, now) {
			return ErrNotFound
		}
		if _, err := tx.TrimStreamEntries(g.Key.ResourceARN, now.Add(-24*time.Hour)); err != nil {
			return err
		}
		sh, err := getStreamShard(tx, g.Key.ResourceARN, it.ShardID)
		if err != nil {
			return err
		}
		point := sh.TrimmedThrough
		if point != "" && (it.Position == "" || compareSequence(it.Position, point) < 0 || it.Inclusive && compareSequence(it.Position, point) == 0) {
			return trimmed()
		}
		entries, err := tx.StreamEntries(StreamEntryQuery{StreamARN: g.Key.ResourceARN, ShardID: sh.ID, Position: it.Position, Inclusive: it.Inclusive, Limit: limit})
		if err != nil {
			return err
		}
		position := it.Position
		inclusive := it.Inclusive
		for _, entry := range entries {
			out.Records = append(out.Records, entry.Data)
			position = entry.Sequence
			inclusive = false
		}
		if !sh.Drained || compareSequence(position, sh.Checkpoint) < 0 || inclusive && compareSequence(position, sh.Checkpoint) == 0 {
			out.NextShardIterator, err = newStreamIterator(ctx, g, sh, position, inclusive, now)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}
