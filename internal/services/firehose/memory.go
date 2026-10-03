package firehose

import (
	"cmp"
	"context"
	"maps"
	"slices"

	api "stackd/internal/awsapi/firehose"
	"stackd/storage/memory"
)

type memoryState struct {
	streams     map[StreamKey]StreamRecord
	streamIDs   map[string]StreamKey
	buffers     map[string]BufferRecord
	records     map[RecordKey]RecordRecord
	checkpoints map[CheckpointKey]CheckpointRecord
	processing  map[string]ProcessingRecord
	metrics     map[MetricPublicationKey]map[metricSampleKey]int64
}

type metricSampleKey struct {
	name  string
	value float64
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{streams: map[StreamKey]StreamRecord{}, streamIDs: map[string]StreamKey{}, buffers: map[string]BufferRecord{}, records: map[RecordKey]RecordRecord{}, checkpoints: map[CheckpointKey]CheckpointRecord{}, processing: map[string]ProcessingRecord{}, metrics: map[MetricPublicationKey]map[metricSampleKey]int64{}}
	return &MemoryRepository{memory.New(domain, initial, func(v memoryState) memoryState {
		v.streams = maps.Clone(v.streams)
		v.streamIDs = maps.Clone(v.streamIDs)
		v.buffers = maps.Clone(v.buffers)
		v.records = maps.Clone(v.records)
		v.checkpoints = maps.Clone(v.checkpoints)
		v.processing = maps.Clone(v.processing)
		v.metrics = maps.Clone(v.metrics)
		for key, samples := range v.metrics {
			v.metrics[key] = maps.Clone(samples)
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

func cloneStream(v StreamRecord) StreamRecord {
	v.Destination = api.CloneExtendedS3DestinationDescription(v.Destination)
	v.Tags = maps.Clone(v.Tags)
	if v.Updated != nil {
		t := *v.Updated
		v.Updated = &t
	}
	if v.Source != nil {
		source := *v.Source
		v.Source = &source
	}
	return v
}
func cloneBuffer(v BufferRecord) BufferRecord {
	if v.Configuration != nil {
		configuration := api.CloneExtendedS3DestinationDescription(*v.Configuration)
		v.Configuration = &configuration
	}
	return v
}
func cloneRecord(v RecordRecord) RecordRecord {
	v.Data = slices.Clone(v.Data)
	if v.Kinesis != nil {
		metadata := *v.Kinesis
		v.Kinesis = &metadata
	}
	return v
}
func compareStreamKeys(a, b StreamKey) int {
	return cmp.Or(cmp.Compare(a.Partition, b.Partition), cmp.Compare(a.AccountID, b.AccountID), cmp.Compare(a.Region, b.Region), cmp.Compare(a.Name, b.Name))
}

func (r memoryReader) Stream(key StreamKey) (StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return StreamRecord{}, err
	}
	v, ok := r.s.streams[key]
	if !ok {
		return StreamRecord{}, ErrNotFound
	}
	return cloneStream(v), nil
}
func (r memoryReader) StreamByID(id string) (StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return StreamRecord{}, err
	}
	key, ok := r.s.streamIDs[id]
	if !ok {
		return StreamRecord{}, ErrNotFound
	}
	return cloneStream(r.s.streams[key]), nil
}
func (r memoryReader) Streams(q StreamQuery) ([]StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []StreamRecord{}
	for key, v := range r.s.streams {
		kind := "DirectPut"
		if v.Source != nil {
			kind = "KinesisStreamAsSource"
		}
		if key.Scope == q.Scope && key.Name > q.After && (q.Type == "" || q.Type == kind) {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b StreamRecord) int { return compareStreamKeys(a.Key, b.Key) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	for i := range out {
		out[i] = cloneStream(out[i])
	}
	return out, nil
}
func (r memoryReader) NextLifecycle() (StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return StreamRecord{}, err
	}
	var selected StreamRecord
	for _, v := range r.s.streams {
		if v.Status != "CREATING" && v.Status != "DELETING" {
			continue
		}
		if selected.ID == "" || v.LifecycleDue.Before(selected.LifecycleDue) || v.LifecycleDue.Equal(selected.LifecycleDue) && v.ID < selected.ID {
			selected = v
		}
	}
	if selected.ID == "" {
		return StreamRecord{}, ErrNotFound
	}
	return cloneStream(selected), nil
}
func (r memoryReader) Buffer(id string) (BufferRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return BufferRecord{}, err
	}
	v, ok := r.s.buffers[id]
	if !ok {
		return BufferRecord{}, ErrNotFound
	}
	return cloneBuffer(v), nil
}
func (r memoryReader) OpenOutputBuffer(streamID string, version int64, kind BufferKind) (BufferRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return BufferRecord{}, err
	}
	var selected BufferRecord
	for _, v := range r.s.buffers {
		if v.StreamID != streamID || v.StreamVersion != version || v.Kind != kind || v.ObjectKey != "" {
			continue
		}
		if selected.ID == "" || v.Created.Before(selected.Created) || v.Created.Equal(selected.Created) && v.ID < selected.ID {
			selected = v
		}
	}
	if selected.ID == "" {
		return BufferRecord{}, ErrNotFound
	}
	return cloneBuffer(selected), nil
}
func (r memoryReader) Records(id string) ([]RecordRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []RecordRecord{}
	for key, v := range r.s.records {
		if key.BufferID == id {
			out = append(out, cloneRecord(v))
		}
	}
	slices.SortFunc(out, func(a, b RecordRecord) int { return cmp.Compare(a.Key.Position, b.Key.Position) })
	return out, nil
}
func (r memoryReader) NextDelivery() (BufferRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return BufferRecord{}, err
	}
	var selected BufferRecord
	for _, v := range r.s.buffers {
		if _, processing := r.s.processing[v.ID]; processing {
			continue
		}
		if selected.ID == "" || v.Due.Before(selected.Due) || v.Due.Equal(selected.Due) && v.ID < selected.ID {
			selected = v
		}
	}
	if selected.ID == "" {
		return BufferRecord{}, ErrNotFound
	}
	return cloneBuffer(selected), nil
}
func (r memoryReader) Processing(id string) (ProcessingRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ProcessingRecord{}, err
	}
	v, ok := r.s.processing[id]
	if !ok {
		return ProcessingRecord{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) NextProcessing() (ProcessingRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ProcessingRecord{}, err
	}
	var selected ProcessingRecord
	for _, v := range r.s.processing {
		if v.State != ProcessingQueued {
			continue
		}
		if selected.BufferID == "" || v.Due.Before(selected.Due) || v.Due.Equal(selected.Due) && v.BufferID < selected.BufferID {
			selected = v
		}
	}
	if selected.BufferID == "" {
		return ProcessingRecord{}, ErrNotFound
	}
	return selected, nil
}
func (r memoryReader) InFlightProcessing() ([]ProcessingRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ProcessingRecord{}
	for _, v := range r.s.processing {
		if v.State == ProcessingInFlight {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b ProcessingRecord) int { return cmp.Compare(a.BufferID, b.BufferID) })
	return out, nil
}
func (r memoryReader) NextSource() (StreamRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return StreamRecord{}, err
	}
	var selected StreamRecord
	for _, v := range r.s.streams {
		if v.Status != "ACTIVE" || v.Source == nil {
			continue
		}
		if selected.ID == "" || v.Source.Due.Before(selected.Source.Due) || v.Source.Due.Equal(selected.Source.Due) && v.ID < selected.ID {
			selected = v
		}
	}
	if selected.ID == "" {
		return StreamRecord{}, ErrNotFound
	}
	return cloneStream(selected), nil
}
func (r memoryReader) Checkpoints(streamID string) ([]CheckpointRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []CheckpointRecord{}
	for key, v := range r.s.checkpoints {
		if key.StreamID == streamID {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b CheckpointRecord) int { return cmp.Compare(a.Key.ShardID, b.Key.ShardID) })
	return out, nil
}
func compareMetricKeys(a, b MetricPublicationKey) int {
	return cmp.Or(a.Minute.Compare(b.Minute), compareStreamKeys(a.Stream, b.Stream))
}
func (r memoryReader) NextMetricPublication() (MetricPublicationKey, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricPublicationKey{}, err
	}
	var selected MetricPublicationKey
	found := false
	for key := range r.s.metrics {
		if !found || compareMetricKeys(key, selected) < 0 {
			selected = key
			found = true
		}
	}
	if !found {
		return MetricPublicationKey{}, ErrNotFound
	}
	return selected, nil
}
func (r memoryReader) MetricSamples(key MetricPublicationKey) ([]MetricSample, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []MetricSample{}
	for key, count := range r.s.metrics[key] {
		out = append(out, MetricSample{Name: key.name, Value: key.value, SampleCount: count})
	}
	slices.SortFunc(out, func(a, b MetricSample) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Value, b.Value)) })
	return out, nil
}

func (w memoryWriter) PutStream(v StreamRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.streams[v.Key] = cloneStream(v)
	w.s.streamIDs[v.ID] = v.Key
	return nil
}
func (w memoryWriter) DeleteStream(key StreamKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v, ok := w.s.streams[key]
	if !ok {
		return nil
	}
	delete(w.s.streams, key)
	delete(w.s.streamIDs, v.ID)
	for id, buffer := range w.s.buffers {
		if buffer.StreamID == v.ID {
			w.deleteBuffer(id)
		}
	}
	for key := range w.s.checkpoints {
		if key.StreamID == v.ID {
			delete(w.s.checkpoints, key)
		}
	}
	return nil
}
func (w memoryWriter) PutBuffer(v BufferRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.buffers[v.ID] = cloneBuffer(v)
	return nil
}
func (w memoryWriter) PutRecord(v RecordRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.records[v.Key] = cloneRecord(v)
	return nil
}
func (w memoryWriter) DeleteBuffer(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.deleteBuffer(id)
	return nil
}
func (w memoryWriter) deleteBuffer(id string) {
	delete(w.s.buffers, id)
	delete(w.s.processing, id)
	for key := range w.s.records {
		if key.BufferID == id {
			delete(w.s.records, key)
		}
	}
}
func (w memoryWriter) PutCheckpoint(v CheckpointRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.checkpoints[v.Key] = v
	return nil
}
func (w memoryWriter) PutProcessing(v ProcessingRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.processing[v.BufferID] = v
	return nil
}
func (w memoryWriter) AddMetricSamples(key MetricPublicationKey, samples []MetricSample) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	group := w.s.metrics[key]
	if group == nil {
		group = map[metricSampleKey]int64{}
		w.s.metrics[key] = group
	}
	for _, sample := range samples {
		group[metricSampleKey{sample.Name, sample.Value}] += sample.SampleCount
	}
	return nil
}
func (w memoryWriter) DeleteMetricPublication(key MetricPublicationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.metrics, key)
	return nil
}

var _ Repository = (*MemoryRepository)(nil)
var _ Reader = memoryReader{}
var _ Transaction = memoryWriter{}
