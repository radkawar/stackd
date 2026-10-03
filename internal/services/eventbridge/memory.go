package eventbridge

import (
	"context"
	"maps"
	"slices"
	"time"

	"stackd/storage/memory"
)

type memoryState struct {
	buses           map[BusKey]BusRecord
	rules           map[RuleKey]RuleRecord
	targets         map[targetKey]TargetRecord
	events          map[string]EventRecord
	deliveries      map[string]DeliveryRecord
	archives        map[ArchiveKey]ArchiveRecord
	archiveEntries  map[archiveEntryKey]ArchiveEntry
	replays         map[ReplayKey]ReplayRecord
	metrics         map[MetricPublicationKey]map[metricSampleKey]int64
	connections     map[ConnectionKey]ConnectionRecord
	apiDestinations map[APIDestinationKey]APIDestinationRecord
}
type targetKey struct {
	Rule RuleKey
	ID   string
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		buses: map[BusKey]BusRecord{}, rules: map[RuleKey]RuleRecord{},
		targets: map[targetKey]TargetRecord{}, events: map[string]EventRecord{},
		deliveries: map[string]DeliveryRecord{}, archives: map[ArchiveKey]ArchiveRecord{},
		archiveEntries: map[archiveEntryKey]ArchiveEntry{}, replays: map[ReplayKey]ReplayRecord{},
		metrics:         map[MetricPublicationKey]map[metricSampleKey]int64{},
		connections:     map[ConnectionKey]ConnectionRecord{},
		apiDestinations: map[APIDestinationKey]APIDestinationRecord{},
	}
	return &MemoryRepository{memory.New(domain, initial, func(s memoryState) memoryState {
		return memoryState{
			buses: maps.Clone(s.buses), rules: maps.Clone(s.rules), targets: maps.Clone(s.targets),
			events: maps.Clone(s.events), deliveries: maps.Clone(s.deliveries),
			archives: maps.Clone(s.archives), archiveEntries: maps.Clone(s.archiveEntries),
			replays:         maps.Clone(s.replays),
			metrics:         maps.Clone(s.metrics),
			connections:     maps.Clone(s.connections),
			apiDestinations: maps.Clone(s.apiDestinations),
		}
	})}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func (r memoryReader) Bus(k BusKey) (BusRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return BusRecord{}, err
	}
	v, ok := r.s.buses[k]
	if !ok {
		return v, ErrNotFound
	}
	v.Tags = maps.Clone(v.Tags)
	v.ConfigurationDataKey = slices.Clone(v.ConfigurationDataKey)
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	return v, nil
}
func (r memoryReader) Buses(scope Scope) ([]BusRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []BusRecord{}
	for k, v := range r.s.buses {
		if k.Scope == scope {
			v.Tags = maps.Clone(v.Tags)
			v.ConfigurationDataKey = slices.Clone(v.ConfigurationDataKey)
			v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b BusRecord) int { return compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) Rule(k RuleKey) (RuleRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return RuleRecord{}, err
	}
	v, ok := r.s.rules[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneRule(v), nil
}
func (r memoryReader) Rules(k BusKey) ([]RuleRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []RuleRecord{}
	for key, v := range r.s.rules {
		if key.Bus == k {
			out = append(out, cloneRule(v))
		}
	}
	slices.SortFunc(out, func(a, b RuleRecord) int { return compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) NextScheduledRule() (RuleRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return RuleRecord{}, false, err
	}
	var next RuleRecord
	found := false
	for _, v := range r.s.rules {
		if v.NextSchedule == nil {
			continue
		}
		if !found || v.NextSchedule.Before(*next.NextSchedule) || v.NextSchedule.Equal(*next.NextSchedule) && compareRuleARN(v.Key, next.Key) < 0 {
			next, found = v, true
		}
	}
	return cloneRule(next), found, nil
}

// Compare the same ARN bytes used by SQLite's due index without allocating ARNs.
func compareRuleARN(a, b RuleKey) int {
	parts := func(k RuleKey) [9]string {
		p := [9]string{k.Bus.Partition, ":events:", k.Bus.Region, ":", k.Bus.Account, ":rule/", "", "", k.Name}
		if k.Bus.Name != "default" {
			p[6], p[7] = k.Bus.Name, "/"
		}
		return p
	}
	left, right := parts(a), parts(b)
	i, j := 0, 0
	for i < len(left) || j < len(right) {
		if i < len(left) && left[i] == "" {
			i++
			continue
		}
		if j < len(right) && right[j] == "" {
			j++
			continue
		}
		if i == len(left) {
			return -1
		}
		if j == len(right) {
			return 1
		}
		n := min(len(left[i]), len(right[j]))
		if c := compare(left[i][:n], right[j][:n]); c != 0 {
			return c
		}
		left[i], right[j] = left[i][n:], right[j][n:]
	}
	return 0
}

func cloneRule(v RuleRecord) RuleRecord {
	v.Tags = maps.Clone(v.Tags)
	v.EncryptedPattern = slices.Clone(v.EncryptedPattern)
	v.NextSchedule = cloneSchedule(v.NextSchedule)
	return v
}

func cloneSchedule(due *time.Time) *time.Time {
	if due == nil {
		return nil
	}
	copy := *due
	return &copy
}
func (r memoryReader) Targets(k RuleKey) ([]TargetRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TargetRecord{}
	for key, v := range r.s.targets {
		if key.Rule == k {
			out = append(out, cloneTarget(v))
		}
	}
	slices.SortFunc(out, func(a, b TargetRecord) int { return compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) RuleNamesByTarget(bus BusKey, arn string) ([]string, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	names := map[string]bool{}
	out := []string{}
	for key, target := range r.s.targets {
		if key.Rule.Bus != bus || target.ARN != arn || names[key.Rule.Name] {
			continue
		}
		names[key.Rule.Name] = true
		out = append(out, key.Rule.Name)
	}
	slices.Sort(out)
	return out, nil
}
func (r memoryReader) Event(id string) (EventRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return EventRecord{}, err
	}
	v, ok := r.s.events[id]
	if !ok {
		return v, ErrNotFound
	}
	v.Resources = slices.Clone(v.Resources)
	v.Payload = cloneArchivePayload(v.Payload)
	v.ConfigurationDataKey = slices.Clone(v.ConfigurationDataKey)
	return v, nil
}
func (r memoryReader) Delivery(id string) (DeliveryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DeliveryRecord{}, err
	}
	v, ok := r.s.deliveries[id]
	if !ok {
		return v, ErrNotFound
	}
	return cloneDelivery(v), nil
}

func (r memoryReader) EventDeliveries(id string) ([]DeliveryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []DeliveryRecord{}
	for _, v := range r.s.deliveries {
		if v.EventID == id {
			out = append(out, cloneDelivery(v))
		}
	}
	slices.SortFunc(out, func(a, b DeliveryRecord) int { return compare(a.ID, b.ID) })
	return out, nil
}
func (r memoryReader) NextDelivery() (DeliveryRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return DeliveryRecord{}, false, err
	}
	var next DeliveryRecord
	found := false
	for _, v := range r.s.deliveries {
		if v.State != "pending" && v.State != "dead-letter" {
			continue
		}
		if !found || v.Due.Before(next.Due) || v.Due.Equal(next.Due) && v.ID < next.ID {
			next, found = v, true
		}
	}
	return cloneDelivery(next), found, nil
}
func (w memoryWriter) PutBus(v BusRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Tags = maps.Clone(v.Tags)
	v.ConfigurationDataKey = slices.Clone(v.ConfigurationDataKey)
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	w.s.buses[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteBus(k BusKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.buses, k)
	return nil
}
func (w memoryWriter) PutRule(v RuleRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.rules[v.Key] = cloneRule(v)
	return nil
}
func (w memoryWriter) UpdateRuleSchedule(k RuleKey, due *time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v, ok := w.s.rules[k]
	if !ok {
		return ErrNotFound
	}
	v.NextSchedule = cloneSchedule(due)
	w.s.rules[k] = v
	return nil
}
func (w memoryWriter) DeleteRule(k RuleKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.rules, k)
	for key := range w.s.targets {
		if key.Rule == k {
			delete(w.s.targets, key)
		}
	}
	return nil
}
func (w memoryWriter) PutTarget(v TargetRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.targets[targetKey{v.Rule, v.ID}] = cloneTarget(v)
	return nil
}

func cloneTarget(v TargetRecord) TargetRecord {
	v.EncryptedConfiguration = slices.Clone(v.EncryptedConfiguration)
	v.EcsParameters = cloneECSParameters(v.EcsParameters)
	v.KinesisParameters = cloneKinesisParameters(v.KinesisParameters)
	v.HttpParameters = cloneHTTPParameters(v.HttpParameters)
	if v.Input.Input != nil {
		input := *v.Input.Input
		v.Input.Input = &input
	}
	if v.Input.InputPath != nil {
		path := *v.Input.InputPath
		v.Input.InputPath = &path
	}
	if v.Input.Transformer != nil {
		transformer := *v.Input.Transformer
		transformer.InputPathsMap = maps.Clone(transformer.InputPathsMap)
		v.Input.Transformer = &transformer
	}
	return v
}
func (w memoryWriter) DeleteTarget(k RuleKey, id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.targets, targetKey{k, id})
	return nil
}
func (w memoryWriter) PutEvent(v EventRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Resources = slices.Clone(v.Resources)
	v.Payload = cloneArchivePayload(v.Payload)
	v.ConfigurationDataKey = slices.Clone(v.ConfigurationDataKey)
	w.s.events[v.ID] = v
	return nil
}
func (w memoryWriter) PutDelivery(v DeliveryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.deliveries[v.ID] = cloneDelivery(v)
	return nil
}
