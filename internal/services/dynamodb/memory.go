package dynamodb

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/storage/memory"
)

type memoryState struct {
	kinesisDestinations      map[string]KinesisDestination
	kinesisDeliveries        map[string]KinesisDelivery
	databases                map[string]DatabaseRecord
	tables                   map[TableKey]TableRecord
	onDemandSwitches         map[TableKey][]time.Time
	backups                  map[BackupKey]BackupRecord
	recoveries               map[string]RecoveryRecord
	recoveryChanges          map[string][]RecoveryChange
	mutationCaptures         map[string]MutationCapture
	mutationVersion          int64
	replicaBootstraps        map[TableKey]ReplicaBootstrap
	replicaBootstrapVersions map[TableKey]map[string]int64
	replicaChanges           map[string][]ReplicaChange
	replicaSequence          int64
	replicaVersions          map[replicaVersionKey]int64
	recoverySequence         int64
	tags                     map[TableKey]TagRecord
	policies                 map[PolicyKey]PolicyRecord
	streams                  map[PolicyKey]StreamGeneration
	shards                   map[string]StreamShard
	entries                  map[string]StreamEntry
	ttlDeletions             map[string]TTLDeletion
	metrics                  map[MetricPublicationKey]map[metricSampleKey]int64
	transactionCapacities    map[TransactionCapacityKey]TransactionCapacity
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		kinesisDestinations:      map[string]KinesisDestination{},
		kinesisDeliveries:        map[string]KinesisDelivery{},
		databases:                map[string]DatabaseRecord{},
		tables:                   map[TableKey]TableRecord{},
		onDemandSwitches:         map[TableKey][]time.Time{},
		backups:                  map[BackupKey]BackupRecord{},
		recoveries:               map[string]RecoveryRecord{},
		recoveryChanges:          map[string][]RecoveryChange{},
		mutationCaptures:         map[string]MutationCapture{},
		replicaBootstraps:        map[TableKey]ReplicaBootstrap{},
		replicaBootstrapVersions: map[TableKey]map[string]int64{},
		replicaChanges:           map[string][]ReplicaChange{},
		replicaVersions:          map[replicaVersionKey]int64{},
		tags:                     map[TableKey]TagRecord{},
		policies:                 map[PolicyKey]PolicyRecord{},
		streams:                  map[PolicyKey]StreamGeneration{}, shards: map[string]StreamShard{},
		entries:               map[string]StreamEntry{},
		ttlDeletions:          map[string]TTLDeletion{},
		metrics:               map[MetricPublicationKey]map[metricSampleKey]int64{},
		transactionCapacities: map[TransactionCapacityKey]TransactionCapacity{},
	}
	return &MemoryRepository{memory.New(domain, initial, func(v memoryState) memoryState {
		return memoryState{
			kinesisDestinations:      maps.Clone(v.kinesisDestinations),
			kinesisDeliveries:        maps.Clone(v.kinesisDeliveries),
			databases:                maps.Clone(v.databases),
			tables:                   maps.Clone(v.tables),
			onDemandSwitches:         maps.Clone(v.onDemandSwitches),
			backups:                  maps.Clone(v.backups),
			recoveries:               maps.Clone(v.recoveries),
			recoveryChanges:          maps.Clone(v.recoveryChanges),
			mutationCaptures:         maps.Clone(v.mutationCaptures),
			mutationVersion:          v.mutationVersion,
			replicaBootstraps:        maps.Clone(v.replicaBootstraps),
			replicaBootstrapVersions: maps.Clone(v.replicaBootstrapVersions),
			replicaChanges:           maps.Clone(v.replicaChanges),
			replicaSequence:          v.replicaSequence,
			replicaVersions:          maps.Clone(v.replicaVersions),
			recoverySequence:         v.recoverySequence,
			tags:                     maps.Clone(v.tags),
			policies:                 maps.Clone(v.policies),
			streams:                  maps.Clone(v.streams), shards: maps.Clone(v.shards),
			entries:               maps.Clone(v.entries),
			ttlDeletions:          maps.Clone(v.ttlDeletions),
			metrics:               cloneMetricSamples(v.metrics),
			transactionCapacities: maps.Clone(v.transactionCapacities),
		}
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

func cloneTableRecord(v TableRecord) TableRecord {
	v.KinesisConsumers = slices.Clone(v.KinesisConsumers)
	v.Data = api.CloneTableDescription(v.Data)
	if v.PendingCreate != nil {
		cloned := api.CloneCreateTableInput(*v.PendingCreate)
		v.PendingCreate = &cloned
	}
	if v.PendingUpdate != nil {
		cloned := api.CloneUpdateTableInput(*v.PendingUpdate)
		v.PendingUpdate = &cloned
	}
	v.TTL = api.CloneTimeToLiveDescription(v.TTL)
	if v.Replica.UnauthorizedAt != nil {
		v.Replica.UnauthorizedAt = new(*v.Replica.UnauthorizedAt)
	}
	return v
}

func (r memoryReader) Database(scope Scope) (DatabaseRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DatabaseRecord{}, err
	}
	for _, v := range r.s.databases {
		if !v.Retiring && v.Spec.Partition == scope.Partition && v.Spec.AccountID == scope.AccountID && v.Spec.Region == scope.Region {
			return v, nil
		}
	}
	return DatabaseRecord{}, ErrNotFound
}

func (r memoryReader) Databases() ([]DatabaseRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]DatabaseRecord, 0, len(r.s.databases))
	for _, v := range r.s.databases {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b DatabaseRecord) int {
		return cmp.Or(
			cmp.Compare(a.Spec.Partition, b.Spec.Partition),
			cmp.Compare(a.Spec.AccountID, b.Spec.AccountID),
			cmp.Compare(a.Spec.Region, b.Spec.Region),
			cmp.Compare(a.Spec.ID, b.Spec.ID),
		)
	})
	return out, nil
}

func (r memoryReader) Table(k TableKey) (TableRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TableRecord{}, err
	}
	v, ok := r.s.tables[k]
	if !ok {
		return TableRecord{}, ErrNotFound
	}
	return cloneTableRecord(v), nil
}

func (r memoryReader) OnDemandSwitches(k TableKey) ([]time.Time, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	return slices.Clone(r.s.onDemandSwitches[k]), nil
}

func (r memoryReader) Tables(q TableQuery) ([]TableRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TableRecord{}
	for k, v := range r.s.tables {
		if k.Scope == q.Scope && k.Name > q.After {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b TableRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	for i := range out {
		out[i] = cloneTableRecord(out[i])
	}
	return out, nil
}

func (r memoryReader) PendingTables() ([]TableRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TableRecord{}
	for _, v := range r.s.tables {
		if v.Data.TableStatus == nil {
			continue
		}
		switch *v.Data.TableStatus {
		case api.TableStatusCREATING, api.TableStatusUPDATING, api.TableStatusDELETING:
			out = append(out, v)
		}
	}
	slices.SortFunc(out, compareTables)
	for i := range out {
		out[i] = cloneTableRecord(out[i])
	}
	return out, nil
}

func compareTables(a, b TableRecord) int {
	return cmp.Or(cmp.Compare(a.Key.Partition, b.Key.Partition), cmp.Compare(a.Key.AccountID, b.Key.AccountID), cmp.Compare(a.Key.Region, b.Key.Region), cmp.Compare(a.Key.Name, b.Key.Name))
}

func (r memoryReader) TTLTables() ([]TableRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var out []TableRecord
	for _, v := range r.s.tables {
		if value(v.TTL.TimeToLiveStatus) == "ENABLED" && (value(v.Data.TableStatus) == "ACTIVE" || value(v.Data.TableStatus) == "UPDATING") {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b TableRecord) int { return cmp.Or(a.TTLNextScan.Compare(b.TTLNextScan), compareTables(a, b)) })
	for i := range out {
		out[i] = cloneTableRecord(out[i])
	}
	return out, nil
}

func (r memoryReader) Tags(k TableKey) (TagRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TagRecord{}, err
	}
	v, ok := r.s.tags[k]
	if !ok {
		return TagRecord{Key: k}, ErrNotFound
	}
	v.Tags = api.CloneTagList(v.Tags)
	return v, nil
}

func (r memoryReader) Policy(k PolicyKey) (PolicyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return PolicyRecord{}, err
	}
	v, ok := r.s.policies[k]
	if !ok {
		return PolicyRecord{}, ErrNotFound
	}
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	return v, nil
}

func (w memoryWriter) PutDatabase(v DatabaseRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if !v.Retiring {
		for id, existing := range w.s.databases {
			if id != v.Spec.ID && !existing.Retiring && existing.Spec.Partition == v.Spec.Partition && existing.Spec.AccountID == v.Spec.AccountID && existing.Spec.Region == v.Spec.Region {
				return errors.New("DynamoDB database already exists in scope")
			}
		}
	}
	w.s.databases[v.Spec.ID] = v
	return nil
}

func (w memoryWriter) DeleteDatabase(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.databases, id)
	delete(w.s.ttlDeletions, id)
	return nil
}

func (w memoryWriter) PutTable(v TableRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.tables[v.Key] = cloneTableRecord(v)
	return nil
}

func (w memoryWriter) PutOnDemandSwitches(k TableKey, times []time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.onDemandSwitches[k] = slices.Clone(times)
	return nil
}

func (w memoryWriter) DeleteTable(k TableKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.tables, k)
	delete(w.s.onDemandSwitches, k)
	delete(w.s.tags, k)
	return nil
}

func (w memoryWriter) PutTags(v TagRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Tags = api.CloneTagList(v.Tags)
	w.s.tags[v.Key] = v
	return nil
}

func (w memoryWriter) PutPolicy(v PolicyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	w.s.policies[v.Key] = v
	return nil
}

func (w memoryWriter) DeletePolicy(k PolicyKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.policies, k)
	return nil
}
