package ebs

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"time"

	api "stackd/internal/awsapi/ebs"
	"stackd/storage/memory"
)

type memoryState struct {
	snapshots    map[SnapshotKey]SnapshotRecord
	blocks       map[BlockKey]BlockRecord
	volumes      map[VolumeKey]VolumeRecord
	volumeBlocks map[VolumeBlockKey]VolumeBlockRecord
	defaults     map[Scope]EncryptionDefault
	publicAccess map[Scope]SnapshotPublicAccess
	sharedTags   map[SharedTagsKey]map[string]string
	counters     map[Scope]uint64
	creations    map[CloudFormationCreationKey]string
}
type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{
		snapshots:    map[SnapshotKey]SnapshotRecord{},
		blocks:       map[BlockKey]BlockRecord{},
		volumes:      map[VolumeKey]VolumeRecord{},
		volumeBlocks: map[VolumeBlockKey]VolumeBlockRecord{},
		defaults:     map[Scope]EncryptionDefault{},
		publicAccess: map[Scope]SnapshotPublicAccess{},
		sharedTags:   map[SharedTagsKey]map[string]string{},
		counters:     map[Scope]uint64{},
		creations:    map[CloudFormationCreationKey]string{},
	}
	return &MemoryRepository{memory.New(domain, initial, func(s memoryState) memoryState {
		s.snapshots = maps.Clone(s.snapshots)
		s.blocks = maps.Clone(s.blocks)
		s.volumes = maps.Clone(s.volumes)
		s.volumeBlocks = maps.Clone(s.volumeBlocks)
		s.defaults = maps.Clone(s.defaults)
		s.publicAccess = maps.Clone(s.publicAccess)
		s.sharedTags = maps.Clone(s.sharedTags)
		s.counters = maps.Clone(s.counters)
		s.creations = maps.Clone(s.creations)
		return s
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
func clonePointer[T any](v *T) *T {
	if v == nil {
		return nil
	}
	return new(*v)
}
func cloneTags(tags api.Tags) api.Tags {
	out := slices.Clone(tags)
	for i := range out {
		out[i].Key = clonePointer(out[i].Key)
		out[i].Value = clonePointer(out[i].Value)
	}
	return out
}
func cloneInput(v api.StartSnapshotRequest) api.StartSnapshotRequest {
	v.ClientToken = clonePointer(v.ClientToken)
	v.Description = clonePointer(v.Description)
	v.Encrypted = clonePointer(v.Encrypted)
	v.KmsKeyArn = clonePointer(v.KmsKeyArn)
	v.ParentSnapshotId = clonePointer(v.ParentSnapshotId)
	v.Timeout = clonePointer(v.Timeout)
	v.VolumeSize = clonePointer(v.VolumeSize)
	v.Tags = cloneTags(v.Tags)
	return v
}
func cloneSnapshot(v SnapshotRecord) SnapshotRecord {
	v.InitialInput = cloneInput(v.InitialInput)
	v.Copy = clonePointer(v.Copy)
	v.Volume = clonePointer(v.Volume)
	v.Tags = maps.Clone(v.Tags)
	v.Shares = slices.Clone(v.Shares)
	v.WrappedKey = slices.Clone(v.WrappedKey)
	v.TokenKey = slices.Clone(v.TokenKey)
	return v
}
func (r memoryReader) Snapshot(k SnapshotKey) (SnapshotRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SnapshotRecord{}, err
	}
	v, ok := r.s.snapshots[k]
	if !ok {
		return SnapshotRecord{}, ErrNotFound
	}
	return cloneSnapshot(v), nil
}
func (r memoryReader) Snapshots(scope Scope) ([]SnapshotRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SnapshotRecord{}
	for k, v := range r.s.snapshots {
		if k.Scope == scope {
			out = append(out, cloneSnapshot(v))
		}
	}
	slices.SortFunc(out, func(a, b SnapshotRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (r memoryReader) RegionalSnapshot(partition, region, id string) (SnapshotRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SnapshotRecord{}, err
	}
	for k, v := range r.s.snapshots {
		if k.Partition == partition && k.Region == region && k.ID == id {
			return cloneSnapshot(v), nil
		}
	}
	return SnapshotRecord{}, ErrNotFound
}
func (r memoryReader) AvailableSnapshots(scope Scope) ([]SnapshotRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SnapshotRecord{}
	for k, v := range r.s.snapshots {
		if k.Partition == scope.Partition && k.Region == scope.Region && (k.AccountID == scope.AccountID || v.Public || slices.ContainsFunc(v.Shares, func(share SnapshotShare) bool {
			return share.AccountID == scope.AccountID && (share.Granted || share.Readable)
		})) {
			out = append(out, cloneSnapshot(v))
		}
	}
	slices.SortFunc(out, func(a, b SnapshotRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (r memoryReader) SnapshotCounts(scope Scope) (SnapshotCounts, error) {
	if err := r.tx.Check(false); err != nil {
		return SnapshotCounts{}, err
	}
	var counts SnapshotCounts
	for k, v := range r.s.snapshots {
		if k.Scope != scope || v.Deleted {
			continue
		}
		counts.Total++
		if v.Status == api.StatusPENDING {
			counts.Pending++
			if v.Copy != nil {
				counts.Copying++
			}
		}
	}
	return counts, nil
}
func (r memoryReader) SnapshotByToken(scope Scope, token string) (SnapshotRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SnapshotRecord{}, err
	}
	for k, v := range r.s.snapshots {
		if k.Scope == scope && token != "" && value(v.InitialInput.ClientToken) == token {
			return cloneSnapshot(v), nil
		}
	}
	return SnapshotRecord{}, ErrNotFound
}
func (r memoryReader) Block(k BlockKey) (BlockRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return BlockRecord{}, err
	}
	v, ok := r.s.blocks[k]
	if !ok {
		return BlockRecord{}, ErrNotFound
	}
	v.Data = slices.Clone(v.Data)
	return v, nil
}
func (r memoryReader) Blocks(k SnapshotKey) ([]BlockInfo, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []BlockInfo{}
	for key, v := range r.s.blocks {
		if key.Snapshot == k {
			out = append(out, v.BlockInfo)
		}
	}
	slices.SortFunc(out, func(a, b BlockInfo) int { return cmp.Compare(a.Key.Index, b.Key.Index) })
	return out, nil
}
func (r memoryReader) EncryptionDefault(scope Scope) (EncryptionDefault, error) {
	if err := r.tx.Check(false); err != nil {
		return EncryptionDefault{}, err
	}
	v, ok := r.s.defaults[scope]
	if !ok {
		return EncryptionDefault{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) SnapshotPublicAccess(scope Scope) (SnapshotPublicAccess, error) {
	if err := r.tx.Check(false); err != nil {
		return SnapshotPublicAccess{}, err
	}
	v, ok := r.s.publicAccess[scope]
	if !ok {
		return SnapshotPublicAccess{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) SharedTags(k SharedTagsKey) (map[string]string, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	return maps.Clone(r.s.sharedTags[k]), nil
}
func (r memoryReader) PendingSnapshotSources(scope Scope) ([]SnapshotKey, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	sources := map[string]bool{}
	for _, v := range r.s.snapshots {
		if snapshotCopyPending(v) && v.Copy.Source.Scope == scope {
			sources[v.Copy.Source.ID] = true
		}
	}
	for _, v := range r.s.volumes {
		if v.Creation != nil && v.Creation.Source.Scope == scope {
			sources[v.Creation.Source.ID] = true
		}
	}
	ids := slices.Sorted(maps.Keys(sources))
	out := make([]SnapshotKey, len(ids))
	for i, id := range ids {
		out[i] = SnapshotKey{Scope: scope, ID: id}
	}
	return out, nil
}

func (r memoryReader) VolumeSnapshotBlocksPending(key VolumeKey) (bool, error) {
	if err := r.tx.Check(false); err != nil {
		return false, err
	}
	for _, v := range r.s.snapshots {
		if volumeSnapshotBlocksPending(v) && v.Volume.Source == key {
			return true, nil
		}
	}
	return false, nil
}

func (r memoryReader) NextWork() (SnapshotRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SnapshotRecord{}, err
	}
	var next SnapshotRecord
	var due time.Time
	for _, v := range r.s.snapshots {
		d := workTime(v)
		if d.IsZero() {
			continue
		}
		if due.IsZero() || d.Before(due) || (d.Equal(due) && compareKeys(v.Key, next.Key) < 0) {
			due = d
			next = v
		}
	}
	if due.IsZero() {
		return SnapshotRecord{}, ErrNotFound
	}
	return cloneSnapshot(next), nil
}
func compareKeys(a, b SnapshotKey) int {
	if c := cmp.Compare(a.Partition, b.Partition); c != 0 {
		return c
	}
	if c := cmp.Compare(a.AccountID, b.AccountID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Region, b.Region); c != 0 {
		return c
	}
	return cmp.Compare(a.ID, b.ID)
}

// SnapshotID gives memory and durable repositories the same scoped ID sequence.
func SnapshotID(scope Scope, sequence uint64) string {
	return resourceID("snap-", scope, sequence)
}

func resourceID(prefix string, scope Scope, sequence uint64) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%s\x00%d", scope.Partition, scope.AccountID, scope.Region, sequence))
	return prefix + hex.EncodeToString(sum[:9])[:17]
}
func (w memoryWriter) NextID(scope Scope) (string, error) {
	return w.nextResourceID("snap-", scope)
}

func (w memoryWriter) nextResourceID(prefix string, scope Scope) (string, error) {
	if err := w.tx.Check(true); err != nil {
		return "", err
	}
	if w.s.counters[scope] == ^uint64(0) {
		return "", fmt.Errorf("ebs: resource ID sequence exhausted")
	}
	w.s.counters[scope]++
	return resourceID(prefix, scope, w.s.counters[scope]), nil
}
func (w memoryWriter) PutSnapshot(v SnapshotRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if prior, ok := w.s.snapshots[v.Key]; ok && prior.CloudFormationOwner.Owner != "" {
		if v.CloudFormationOwner.Owner != "" && v.CloudFormationOwner != prior.CloudFormationOwner {
			return ownershipFailure()
		}
		v.CloudFormationOwner = prior.CloudFormationOwner
	}
	w.s.snapshots[v.Key] = cloneSnapshot(v)
	return nil
}
func (w memoryWriter) DeleteSnapshot(k SnapshotKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.snapshots[k]; !ok {
		return ErrNotFound
	}
	delete(w.s.snapshots, k)
	for key := range w.s.sharedTags {
		if key.Snapshot == k {
			delete(w.s.sharedTags, key)
		}
	}
	return w.DeleteBlocks(k)
}
func (w memoryWriter) PutBlock(v BlockRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v.Data = slices.Clone(v.Data)
	w.s.blocks[v.Key] = v
	return nil
}
func (w memoryWriter) DeleteBlocks(k SnapshotKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key := range w.s.blocks {
		if key.Snapshot == k {
			delete(w.s.blocks, key)
		}
	}
	return nil
}
func (w memoryWriter) PutEncryptionDefault(v EncryptionDefault) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.defaults[v.Scope] = v
	return nil
}
func (w memoryWriter) PutSnapshotPublicAccess(v SnapshotPublicAccess) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.publicAccess[v.Scope] = v
	return nil
}
func (w memoryWriter) PutSharedTags(k SharedTagsKey, tags map[string]string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if len(tags) == 0 {
		delete(w.s.sharedTags, k)
	} else {
		w.s.sharedTags[k] = maps.Clone(tags)
	}
	return nil
}

var _ Repository = (*MemoryRepository)(nil)

func (r memoryReader) TagsForAccount(scope Scope) ([]SnapshotTag, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var tags []SnapshotTag
	for key, snapshot := range r.s.snapshots {
		if key.Scope == scope && !snapshot.Deleted {
			for name, value := range snapshot.Tags {
				tags = append(tags, SnapshotTag{Snapshot: key, Key: name, Value: value})
			}
		}
	}
	for key, values := range r.s.sharedTags {
		snapshot := key.Snapshot
		if snapshot.Partition != scope.Partition || snapshot.Region != scope.Region || key.AccountID != scope.AccountID || r.s.snapshots[snapshot].Deleted {
			continue
		}
		for name, value := range values {
			tags = append(tags, SnapshotTag{Snapshot: snapshot, Key: name, Value: value})
		}
	}
	slices.SortFunc(tags, func(a, b SnapshotTag) int {
		if c := cmp.Compare(a.Snapshot.ID, b.Snapshot.ID); c != 0 {
			return c
		}
		return cmp.Compare(a.Key, b.Key)
	})
	return tags, nil
}
