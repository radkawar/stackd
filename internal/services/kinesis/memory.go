package kinesis

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"time"

	api "stackd/internal/awsapi/kinesis"
	"stackd/storage/memory"
)

type memoryState struct {
	streams   map[StreamKey]StreamRecord
	shards    map[ShardKey]ShardRecord
	consumers map[ConsumerKey]ConsumerRecord
	tags      map[ResourceKey]TagRecord
	policies  map[ResourceKey]PolicyRecord
	accounts  map[Scope]AccountRecord
	switches  map[StreamKey][]time.Time
	metrics   map[MetricPublicationKey]map[metricSampleKey]int64
}
type metricSampleKey struct {
	consumer, shard, name string
	value                 float64
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		streams: map[StreamKey]StreamRecord{}, shards: map[ShardKey]ShardRecord{},
		consumers: map[ConsumerKey]ConsumerRecord{}, tags: map[ResourceKey]TagRecord{},
		policies: map[ResourceKey]PolicyRecord{}, accounts: map[Scope]AccountRecord{},
		switches: map[StreamKey][]time.Time{}, metrics: map[MetricPublicationKey]map[metricSampleKey]int64{},
	}
	return &MemoryRepository{memory.New(domain, initial, func(v memoryState) memoryState {
		v.streams = maps.Clone(v.streams)
		v.shards = maps.Clone(v.shards)
		v.consumers = maps.Clone(v.consumers)
		v.tags = maps.Clone(v.tags)
		v.policies = maps.Clone(v.policies)
		v.accounts = maps.Clone(v.accounts)
		v.switches = maps.Clone(v.switches)
		v.metrics = maps.Clone(v.metrics)
		for k, samples := range v.metrics {
			v.metrics[k] = maps.Clone(samples)
		}
		return v
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func cloneStreamRecord(v StreamRecord) StreamRecord {
	v.Data = api.CloneStreamDescriptionSummary(v.Data)
	v.ShardCountUpdates = slices.Clone(v.ShardCountUpdates)
	v.EncryptionUpdates = slices.Clone(v.EncryptionUpdates)
	if v.Pending != nil {
		p := *v.Pending
		p.Monitoring = slices.Clone(p.Monitoring)
		if p.WarmMiBps != nil {
			x := *p.WarmMiBps
			p.WarmMiBps = &x
		}
		v.Pending = &p
	}
	return v
}
func cloneShardRecord(v ShardRecord) ShardRecord { v.Data = api.CloneShard(v.Data); return v }
func cloneConsumerRecord(v ConsumerRecord) ConsumerRecord {
	v.Data = api.CloneConsumerDescription(v.Data)
	return v
}
func cloneTagRecord(v TagRecord) TagRecord { v.Tags = api.CloneTagList(v.Tags); return v }
func clonePolicyRecord(v PolicyRecord) PolicyRecord {
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	v.Effective.PrincipalIDs = maps.Clone(v.Effective.PrincipalIDs)
	return v
}
func cloneAccountRecord(v AccountRecord) AccountRecord {
	v.Commitment = api.CloneMinimumThroughputBillingCommitmentOutput(v.Commitment)
	return v
}
func compareStreamKeys(a, b StreamKey) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.Name, b.Name))
}
func (r memoryReader) Stream(k StreamKey) (StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return StreamRecord{}, err
	}
	v, ok := r.s.streams[k]
	if !ok {
		return StreamRecord{}, ErrNotFound
	}
	return cloneStreamRecord(v), nil
}
func (r memoryReader) Streams(q StreamQuery) ([]StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []StreamRecord{}
	for k, v := range r.s.streams {
		if k.Scope == q.Scope && k.Name > q.After {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b StreamRecord) int { return compareStreamKeys(a.Key, b.Key) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	for i := range out {
		out[i] = cloneStreamRecord(out[i])
	}
	return out, nil
}
func (r memoryReader) AllStreams() ([]StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]StreamRecord, 0, len(r.s.streams))
	for _, v := range r.s.streams {
		out = append(out, cloneStreamRecord(v))
	}
	slices.SortFunc(out, func(a, b StreamRecord) int { return compareStreamKeys(a.Key, b.Key) })
	return out, nil
}
func (r memoryReader) Shards(k StreamKey) ([]ShardRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ShardRecord{}
	for key, v := range r.s.shards {
		if key.Stream == k {
			out = append(out, cloneShardRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b ShardRecord) int { return cmp.Compare(a.Key.Partition, b.Key.Partition) })
	return out, nil
}
func (r memoryReader) Consumer(k ConsumerKey) (ConsumerRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ConsumerRecord{}, err
	}
	v, ok := r.s.consumers[k]
	if !ok {
		return ConsumerRecord{}, ErrNotFound
	}
	return cloneConsumerRecord(v), nil
}
func (r memoryReader) Consumers(k StreamKey) ([]ConsumerRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ConsumerRecord{}
	for key, v := range r.s.consumers {
		if key.Stream == k {
			out = append(out, cloneConsumerRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b ConsumerRecord) int {
		return cmp.Or(cmp.Compare(a.Key.Name, b.Key.Name), cmp.Compare(a.Key.CreatedAt, b.Key.CreatedAt))
	})
	return out, nil
}
func (r memoryReader) Tags(k ResourceKey) (TagRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TagRecord{}, err
	}
	v, ok := r.s.tags[k]
	if !ok {
		return TagRecord{Key: k}, ErrNotFound
	}
	return cloneTagRecord(v), nil
}
func (r memoryReader) Policy(k ResourceKey) (PolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PolicyRecord{}, err
	}
	v, ok := r.s.policies[k]
	if !ok {
		return PolicyRecord{}, ErrNotFound
	}
	return clonePolicyRecord(v), nil
}
func (r memoryReader) Account(k Scope) (AccountRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return AccountRecord{}, err
	}
	v, ok := r.s.accounts[k]
	if !ok {
		return AccountRecord{}, ErrNotFound
	}
	return cloneAccountRecord(v), nil
}
func (r memoryReader) ModeSwitches(k StreamKey) ([]time.Time, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	return slices.Clone(r.s.switches[k]), nil
}
func (w memoryWriter) PutStream(v StreamRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.streams[v.Key] = cloneStreamRecord(v)
	return nil
}
func (w memoryWriter) PutShard(v ShardRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.shards[v.Key] = cloneShardRecord(v)
	return nil
}
func (w memoryWriter) PutConsumer(v ConsumerRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.consumers[v.Key] = cloneConsumerRecord(v)
	return nil
}
func (w memoryWriter) PutTags(v TagRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.tags[v.Key] = cloneTagRecord(v)
	return nil
}
func (w memoryWriter) PutPolicy(v PolicyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.policies[v.Key] = clonePolicyRecord(v)
	return nil
}
func (w memoryWriter) PutAccount(v AccountRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.accounts[v.Scope] = cloneAccountRecord(v)
	return nil
}
func (w memoryWriter) PutModeSwitches(k StreamKey, v []time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.switches[k] = slices.Clone(v)
	return nil
}
func (w memoryWriter) DeletePolicy(k ResourceKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.policies, k)
	return nil
}
func (w memoryWriter) DeleteConsumer(k ConsumerKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.consumers, k)
	rk := ResourceKey{Scope: k.Stream.Scope, ARN: k.ARN()}
	delete(w.s.tags, rk)
	delete(w.s.policies, rk)
	return nil
}
func (w memoryWriter) DeleteStream(k StreamKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.streams, k)
	for key := range w.s.shards {
		if key.Stream == k {
			delete(w.s.shards, key)
		}
	}
	for key := range w.s.consumers {
		if key.Stream == k {
			if err := w.DeleteConsumer(key); err != nil {
				return err
			}
		}
	}
	rk := ResourceKey{Scope: k.Scope, ARN: k.ARN()}
	delete(w.s.tags, rk)
	delete(w.s.policies, rk)
	return nil
}
func (r memoryReader) NextMetricPublication() (MetricPublicationKey, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricPublicationKey{}, err
	}
	var next MetricPublicationKey
	found := false
	for k := range r.s.metrics {
		if !found || cmp.Or(k.Minute.Compare(next.Minute), compareStreamKeys(k.Stream, next.Stream)) < 0 {
			next, found = k, true
		}
	}
	if !found {
		return next, ErrNotFound
	}
	return next, nil
}
func (r memoryReader) MetricSamples(k MetricPublicationKey) ([]MetricSample, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	k.Minute = k.Minute.UTC()
	out := make([]MetricSample, 0, len(r.s.metrics[k]))
	for v, n := range r.s.metrics[k] {
		out = append(out, MetricSample{ConsumerName: v.consumer, ShardID: v.shard, Name: v.name, Value: v.value, SampleCount: n})
	}
	slices.SortFunc(out, func(a, b MetricSample) int {
		return cmp.Or(cmp.Compare(a.ConsumerName, b.ConsumerName), cmp.Compare(a.ShardID, b.ShardID), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Value, b.Value))
	})
	return out, nil
}
func (w memoryWriter) AddMetricSamples(k MetricPublicationKey, samples []MetricSample) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	k.Minute = k.Minute.UTC()
	group := w.s.metrics[k]
	if group == nil {
		group = make(map[metricSampleKey]int64, len(samples))
		w.s.metrics[k] = group
	}
	for _, v := range samples {
		group[metricSampleKey{v.ConsumerName, v.ShardID, v.Name, v.Value}] += v.SampleCount
	}
	return nil
}
func (w memoryWriter) DeleteMetricPublication(k MetricPublicationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	k.Minute = k.Minute.UTC()
	delete(w.s.metrics, k)
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
var _ Reader = memoryReader{}
var _ Transaction = memoryWriter{}
