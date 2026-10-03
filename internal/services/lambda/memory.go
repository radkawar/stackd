package lambda

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"stackd/storage/memory"
)

type deploymentKey struct {
	FunctionKey
	Pending bool
	Version uint64
}
type MemoryRepository struct {
	store                 *memory.Store[map[deploymentKey]FunctionRecord]
	policies              *memory.Store[map[FunctionReference]FunctionPolicy]
	configs               *memory.Store[map[FunctionReference]EventInvokeConfig]
	urls                  *memory.Store[functionURLState]
	mappings              *memory.Store[map[EventSourceMappingKey]EventSourceMappingRecord]
	streamShards          *memory.Store[map[StreamShardKey]StreamShardRecord]
	streamFailures        *memory.Store[map[string]StreamFailure]
	aliases               *memory.Store[map[FunctionReference]AliasRecord]
	allocations           *memory.Store[map[FunctionKey]uint64]
	versionOwners         *memory.Store[versionOwnerState]
	invocations           *memory.Store[map[string]InvocationRecord]
	outcomes              *memory.Store[map[string]OutcomeDeliveryRecord]
	metrics               *memory.Store[map[MetricPublicationKey]map[metricSampleKey]int64]
	concurrency           *memory.Store[map[FunctionKey]int32]
	archives              *memory.Store[map[CodeArchiveKey]CodeArchive]
	signingKeys           *memory.Store[map[Scope]CodeSigningKey]
	layers                *memory.Store[map[LayerVersionKey]LayerVersionRecord]
	layerAllocations      *memory.Store[map[LayerKey]uint64]
	layerPolicies         *memory.Store[map[LayerVersionKey]LayerPolicy]
	layerPermissionOwners *memory.Store[map[LayerPermissionKey]LayerPermissionOwner]
	documentDBCheckpoints *memory.Store[map[EventSourceMappingKey]DocumentDBCheckpoint]
	runtimeControls       *memory.Store[runtimeControlState]
	codeSigning           *memory.Store[codeSigningState]
	durable               *memory.Store[map[string]DurableExecutionRecord]
	capacity              *memory.Store[capacityState]
}

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	if domain == nil {
		domain = memory.NewDomain()
	}
	return &MemoryRepository{
		store:                 memory.New(domain, map[deploymentKey]FunctionRecord{}, maps.Clone[map[deploymentKey]FunctionRecord]),
		policies:              memory.New(domain, map[FunctionReference]FunctionPolicy{}, maps.Clone[map[FunctionReference]FunctionPolicy]),
		configs:               memory.New(domain, map[FunctionReference]EventInvokeConfig{}, maps.Clone[map[FunctionReference]EventInvokeConfig]),
		urls:                  memory.New(domain, functionURLState{Records: map[FunctionReference]FunctionURLRecord{}, IDs: map[string]FunctionReference{}}, cloneFunctionURLState),
		mappings:              memory.New(domain, map[EventSourceMappingKey]EventSourceMappingRecord{}, maps.Clone[map[EventSourceMappingKey]EventSourceMappingRecord]),
		streamShards:          memory.New(domain, map[StreamShardKey]StreamShardRecord{}, maps.Clone[map[StreamShardKey]StreamShardRecord]),
		streamFailures:        memory.New(domain, map[string]StreamFailure{}, maps.Clone[map[string]StreamFailure]),
		aliases:               memory.New(domain, map[FunctionReference]AliasRecord{}, maps.Clone[map[FunctionReference]AliasRecord]),
		allocations:           memory.New(domain, map[FunctionKey]uint64{}, maps.Clone[map[FunctionKey]uint64]),
		versionOwners:         newVersionOwnerStore(domain),
		invocations:           memory.New(domain, map[string]InvocationRecord{}, maps.Clone[map[string]InvocationRecord]),
		outcomes:              memory.New(domain, map[string]OutcomeDeliveryRecord{}, maps.Clone[map[string]OutcomeDeliveryRecord]),
		metrics:               memory.New(domain, map[MetricPublicationKey]map[metricSampleKey]int64{}, cloneMetricSamples),
		concurrency:           memory.New(domain, map[FunctionKey]int32{}, maps.Clone[map[FunctionKey]int32]),
		archives:              memory.New(domain, map[CodeArchiveKey]CodeArchive{}, maps.Clone[map[CodeArchiveKey]CodeArchive]),
		signingKeys:           memory.New(domain, map[Scope]CodeSigningKey{}, maps.Clone[map[Scope]CodeSigningKey]),
		layers:                memory.New(domain, map[LayerVersionKey]LayerVersionRecord{}, maps.Clone[map[LayerVersionKey]LayerVersionRecord]),
		layerAllocations:      memory.New(domain, map[LayerKey]uint64{}, maps.Clone[map[LayerKey]uint64]),
		layerPolicies:         memory.New(domain, map[LayerVersionKey]LayerPolicy{}, maps.Clone[map[LayerVersionKey]LayerPolicy]),
		layerPermissionOwners: memory.New(domain, map[LayerPermissionKey]LayerPermissionOwner{}, maps.Clone[map[LayerPermissionKey]LayerPermissionOwner]),
		documentDBCheckpoints: memory.New(domain, map[EventSourceMappingKey]DocumentDBCheckpoint{}, maps.Clone[map[EventSourceMappingKey]DocumentDBCheckpoint]),
		runtimeControls:       newRuntimeControlStore(domain),
		codeSigning:           newCodeSigningStore(domain),
		durable:               memory.New(domain, map[string]DurableExecutionRecord{}, maps.Clone[map[string]DurableExecutionRecord]),
		capacity:              newCapacityStore(domain),
	}
}
func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(state *map[deploymentKey]FunctionRecord, tx *memory.Transaction) error {
		return fn(memoryReader{state: state, tx: tx, repository: m})
	})
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(state *map[deploymentKey]FunctionRecord, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{state: state, tx: tx, repository: m}})
	})
}

type memoryReader struct {
	state      *map[deploymentKey]FunctionRecord
	tx         *memory.Transaction
	repository *MemoryRepository
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }
func cloneFunction(v FunctionRecord) FunctionRecord {
	v.Variables = maps.Clone(v.Variables)
	v.Tags = maps.Clone(v.Tags)
	v.Layers = slices.Clone(v.Layers)
	v.Reference = cloneS3Reference(v.Reference)
	v.Durable = cloneDurableConfig(v.Durable)
	v.Capacity = cloneCapacityFunction(v.Capacity)
	return v
}
func (r memoryReader) Function(k FunctionKey) (FunctionRecord, error) {
	return r.function(deploymentKey{FunctionKey: k})
}
func (r memoryReader) PendingFunction(k FunctionKey) (FunctionRecord, error) {
	return r.function(deploymentKey{FunctionKey: k, Pending: true})
}
func (r memoryReader) function(k deploymentKey) (FunctionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return FunctionRecord{}, err
	}
	v, ok := (*r.state)[k]
	if !ok {
		return FunctionRecord{}, ErrNotFound
	}
	return cloneFunction(v), nil
}
func (r memoryReader) Functions(scope Scope) ([]FunctionRecord, error) {
	return r.functions(&scope, false)
}
func (r memoryReader) AllFunctions() ([]FunctionRecord, error)     { return r.functions(nil, false) }
func (r memoryReader) PendingFunctions() ([]FunctionRecord, error) { return r.functions(nil, true) }
func (r memoryReader) functions(scope *Scope, pending bool) ([]FunctionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []FunctionRecord{}
	for k, v := range *r.state {
		if k.Version == 0 && k.Pending == pending && (scope == nil || k.Scope == *scope) {
			out = append(out, cloneFunction(v))
		}
	}
	slices.SortFunc(out, func(a, b FunctionRecord) int {
		return cmp.Or(cmp.Compare(a.Key.Partition, b.Key.Partition), cmp.Compare(a.Key.Account, b.Key.Account), cmp.Compare(a.Key.Region, b.Key.Region), cmp.Compare(a.Key.Name, b.Key.Name))
	})
	return out, nil
}
func (w memoryWriter) PutFunction(v FunctionRecord) error        { return w.put(v, false) }
func (w memoryWriter) PutPendingFunction(v FunctionRecord) error { return w.put(v, true) }
func (w memoryWriter) put(v FunctionRecord, pending bool) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Version = 0
	(*w.state)[deploymentKey{FunctionKey: v.Key, Pending: pending}] = cloneFunction(v)
	return nil
}
func (w memoryWriter) DeleteFunction(k FunctionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if err := w.detachFunctionInvocations(k); err != nil {
		return err
	}
	for key := range *w.state {
		if key.FunctionKey == k {
			delete(*w.state, key)
		}
	}
	if err := w.deleteFunctionVersionOwners(k, 0); err != nil {
		return err
	}
	if err := w.deleteFunctionControls(k); err != nil {
		return err
	}
	if err := w.deleteFunctionURLs(k); err != nil {
		return err
	}
	if err := w.DeleteFunctionConcurrency(k); err != nil {
		return err
	}
	if err := w.deleteRuntimeControls(k); err != nil {
		return err
	}
	if err := w.DeleteFunctionCodeSigningConfig(k); err != nil {
		return err
	}
	return nil
}
func (w memoryWriter) DeletePendingFunction(k FunctionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(*w.state, deploymentKey{FunctionKey: k, Pending: true})
	return nil
}
