package s3

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"stackd/storage/memory"
)

// MemoryRepository stores immutable records in one shared transaction domain.
type MemoryRepository struct {
	buckets             *memory.Store[map[BucketKey]BucketRecord]
	tags                *memory.Store[map[BucketKey][]Tag]
	cors                *memory.Store[map[BucketKey][]CORSRule]
	websites            *memory.Store[map[BucketKey]WebsiteConfiguration]
	logging             *memory.Store[map[BucketKey]LoggingConfiguration]
	replication         *memory.Store[map[BucketKey]ReplicationConfiguration]
	lifecycle           *memory.Store[map[BucketKey]LifecycleConfiguration]
	tiering             *memory.Store[map[memoryTieringKey]TieringConfiguration]
	tieringScans        *memory.Store[map[BucketKey]time.Time]
	requestMetrics      *memory.Store[map[BucketKey]map[string]RequestMetricsConfiguration]
	inventory           *memory.Store[map[BucketKey]map[string]InventoryConfiguration]
	analytics           *memory.Store[map[BucketKey]map[string]AnalyticsConfiguration]
	replicationStates   *memory.Store[map[memoryReplicationStateKey]ReplicationState]
	replicationJobs     *memory.Store[map[int64]ReplicationJob]
	replicationMetrics  *memory.Store[map[memoryReplicationMetricKey]ReplicationMetricPublication]
	objectTags          *memory.Store[map[ObjectVersionKey][]Tag]
	objects             *memory.Store[map[ObjectVersionKey]ObjectRecord]
	data                *memory.Store[map[ObjectVersionKey][][]byte]
	objectParts         *memory.Store[map[ObjectVersionKey][]PartRecord]
	objectRestores      *memory.Store[map[ObjectVersionKey]ObjectRestore]
	uploads             *memory.Store[map[MultipartUploadKey]MultipartUploadRecord]
	uploadParts         *memory.Store[map[MultipartUploadKey]map[int32]memoryMultipartPart]
	sequence            *memory.Store[int64]
	notifications       *memory.Store[map[BucketKey]NotificationState]
	deliveries          *memory.Store[map[string]NotificationDelivery]
	accessLogs          *memory.Store[map[string]AccessLogDelivery]
	accountPublicAccess *memory.Store[map[accountPublicAccessKey]PublicAccessBlock]
	accessPoints        *memory.Store[map[AccessPointKey]AccessPointRecord]
	accessPointAliases  *memory.Store[map[accessPointAliasKey]AccessPointKey]
	accessPointTags     *memory.Store[map[AccessPointKey][]Tag]
}

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	if domain == nil {
		domain = memory.NewDomain()
	}
	return &MemoryRepository{
		buckets:             memory.New(domain, map[BucketKey]BucketRecord{}, maps.Clone[map[BucketKey]BucketRecord]),
		tags:                memory.New(domain, map[BucketKey][]Tag{}, maps.Clone[map[BucketKey][]Tag]),
		cors:                memory.New(domain, map[BucketKey][]CORSRule{}, maps.Clone[map[BucketKey][]CORSRule]),
		websites:            memory.New(domain, map[BucketKey]WebsiteConfiguration{}, maps.Clone[map[BucketKey]WebsiteConfiguration]),
		logging:             memory.New(domain, map[BucketKey]LoggingConfiguration{}, maps.Clone[map[BucketKey]LoggingConfiguration]),
		replication:         memory.New(domain, map[BucketKey]ReplicationConfiguration{}, maps.Clone[map[BucketKey]ReplicationConfiguration]),
		lifecycle:           memory.New(domain, map[BucketKey]LifecycleConfiguration{}, maps.Clone[map[BucketKey]LifecycleConfiguration]),
		tiering:             memory.New(domain, map[memoryTieringKey]TieringConfiguration{}, maps.Clone[map[memoryTieringKey]TieringConfiguration]),
		tieringScans:        memory.New(domain, map[BucketKey]time.Time{}, maps.Clone[map[BucketKey]time.Time]),
		requestMetrics:      memory.New(domain, map[BucketKey]map[string]RequestMetricsConfiguration{}, memory.CloneTables[BucketKey, string, RequestMetricsConfiguration]),
		inventory:           memory.New(domain, map[BucketKey]map[string]InventoryConfiguration{}, memory.CloneTables[BucketKey, string, InventoryConfiguration]),
		analytics:           memory.New(domain, map[BucketKey]map[string]AnalyticsConfiguration{}, memory.CloneTables[BucketKey, string, AnalyticsConfiguration]),
		replicationStates:   memory.New(domain, map[memoryReplicationStateKey]ReplicationState{}, maps.Clone[map[memoryReplicationStateKey]ReplicationState]),
		replicationJobs:     memory.New(domain, map[int64]ReplicationJob{}, maps.Clone[map[int64]ReplicationJob]),
		replicationMetrics:  memory.New(domain, map[memoryReplicationMetricKey]ReplicationMetricPublication{}, maps.Clone[map[memoryReplicationMetricKey]ReplicationMetricPublication]),
		objectTags:          memory.New(domain, map[ObjectVersionKey][]Tag{}, maps.Clone[map[ObjectVersionKey][]Tag]),
		objects:             memory.New(domain, map[ObjectVersionKey]ObjectRecord{}, maps.Clone[map[ObjectVersionKey]ObjectRecord]),
		data:                memory.New(domain, map[ObjectVersionKey][][]byte{}, maps.Clone[map[ObjectVersionKey][][]byte]),
		objectParts:         memory.New(domain, map[ObjectVersionKey][]PartRecord{}, maps.Clone[map[ObjectVersionKey][]PartRecord]),
		objectRestores:      memory.New(domain, map[ObjectVersionKey]ObjectRestore{}, maps.Clone[map[ObjectVersionKey]ObjectRestore]),
		uploads:             memory.New(domain, map[MultipartUploadKey]MultipartUploadRecord{}, maps.Clone[map[MultipartUploadKey]MultipartUploadRecord]),
		uploadParts:         memory.New(domain, map[MultipartUploadKey]map[int32]memoryMultipartPart{}, memory.CloneTables[MultipartUploadKey, int32, memoryMultipartPart]),
		sequence:            memory.New(domain, int64(0), func(v int64) int64 { return v }),
		notifications:       memory.New(domain, map[BucketKey]NotificationState{}, maps.Clone[map[BucketKey]NotificationState]),
		deliveries:          memory.New(domain, map[string]NotificationDelivery{}, maps.Clone[map[string]NotificationDelivery]),
		accessLogs:          memory.New(domain, map[string]AccessLogDelivery{}, maps.Clone[map[string]AccessLogDelivery]),
		accountPublicAccess: memory.New(domain, map[accountPublicAccessKey]PublicAccessBlock{}, maps.Clone[map[accountPublicAccessKey]PublicAccessBlock]),
		accessPoints:        memory.New(domain, map[AccessPointKey]AccessPointRecord{}, maps.Clone[map[AccessPointKey]AccessPointRecord]),
		accessPointAliases:  memory.New(domain, map[accessPointAliasKey]AccessPointKey{}, maps.Clone[map[accessPointAliasKey]AccessPointKey]),
		accessPointTags:     memory.New(domain, map[AccessPointKey][]Tag{}, maps.Clone[map[AccessPointKey][]Tag]),
	}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.buckets.View(ctx, func(state *map[BucketKey]BucketRecord, tx *memory.Transaction) error {
		return fn(memoryReader{state: state, tx: tx, repository: m})
	})
}

func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.buckets.Update(ctx, func(state *map[BucketKey]BucketRecord, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{state: state, tx: tx, repository: m}})
	})
}

func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.buckets.Attempt(ctx, func(state *map[BucketKey]BucketRecord, tx *memory.Transaction) error {
		return fn(memoryWriter{memoryReader{state: state, tx: tx, repository: m}})
	})
}

type memoryReader struct {
	state      *map[BucketKey]BucketRecord
	tx         *memory.Transaction
	repository *MemoryRepository
}

type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func cloneACL(v *AccessControlList) *AccessControlList {
	if v == nil {
		return nil
	}
	out := *v
	out.Grants = slices.Clone(v.Grants)
	return &out
}

func cloneBucket(v BucketRecord) BucketRecord {
	v.ACL = cloneACL(v.ACL)
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	if v.PublicAccess != nil {
		access := *v.PublicAccess
		v.PublicAccess = &access
	}
	return v
}

func cloneObject(v ObjectRecord, includeKey bool) ObjectRecord {
	v.ACL = cloneACL(v.ACL)
	v.Metadata = maps.Clone(v.Metadata)
	v.Tiering = copyOptional(v.Tiering)
	if v.Expires != nil {
		expires := *v.Expires
		v.Expires = &expires
	}
	if includeKey {
		v.EncryptionKey = slices.Clone(v.EncryptionKey)
		if v.CustomerKey != nil {
			v.CustomerKey = &CustomerKeyVerifier{
				Salt: slices.Clone(v.CustomerKey.Salt),
				Hash: slices.Clone(v.CustomerKey.Hash),
				MD5:  v.CustomerKey.MD5,
			}
		}
		v.EncryptionContext = maps.Clone(v.EncryptionContext)
	} else {
		v.EncryptionKey = nil
		v.EncryptionContext = nil
		v.CustomerKey = nil
	}
	return v
}

func (r memoryReader) Bucket(key BucketKey) (BucketRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return BucketRecord{}, err
	}
	v, ok := (*r.state)[key]
	if !ok {
		return BucketRecord{}, ErrNotFound
	}
	return cloneBucket(v), nil
}

func (r memoryReader) Buckets(partition, accountID string) ([]BucketRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []BucketRecord{}
	for key, v := range *r.state {
		if key.Partition == partition && v.AccountID == accountID {
			out = append(out, cloneBucket(v))
		}
	}
	slices.SortFunc(out, func(a, b BucketRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}

func (r memoryReader) BucketTags(key BucketKey) ([]Tag, error) {
	var out []Tag
	err := r.repository.tags.View(r.Context(), func(state *map[BucketKey][]Tag, _ *memory.Transaction) error {
		out = slices.Clone((*state)[key])
		return nil
	})
	return out, err
}

func (w memoryWriter) ReplaceBucketTags(key BucketKey, tags []Tag) error {
	return w.repository.tags.Update(w.Context(), func(state *map[BucketKey][]Tag, _ *memory.Transaction) error {
		if len(tags) == 0 {
			delete(*state, key)
		} else {
			(*state)[key] = slices.Clone(tags)
		}
		return nil
	})
}

func (r memoryReader) Object(key ObjectKey) (ObjectRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ObjectRecord{}, err
	}
	var out ObjectRecord
	err := r.repository.objects.View(r.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		for version, v := range *state {
			if version.ObjectKey == key && v.CreatedOrder > out.CreatedOrder {
				out = v
			}
		}
		if out.CreatedOrder == 0 {
			return ErrNotFound
		}
		out = cloneObject(out, true)
		return nil
	})
	return out, err
}

func (r memoryReader) ObjectVersion(key ObjectVersionKey) (ObjectRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ObjectRecord{}, err
	}
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	var out ObjectRecord
	err := r.repository.objects.View(r.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		v, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		out = cloneObject(v, true)
		return nil
	})
	return out, err
}

func (r memoryReader) ObjectVersions(query VersionQuery) ([]ObjectRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ObjectRecord{}
	if query.Limit <= 0 {
		return out, nil
	}
	err := r.repository.objects.View(r.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		var cursor int64
		if query.AfterOrder != nil {
			cursor = *query.AfterOrder
		} else if query.AfterVersion != "" {
			cursor = (*state)[ObjectVersionKey{ObjectKey: ObjectKey{Bucket: query.Bucket, Name: query.AfterKey}, VersionID: query.AfterVersion}].CreatedOrder
		}
		for key, v := range *state {
			if key.Bucket != query.Bucket || !strings.HasPrefix(key.Name, query.Prefix) {
				continue
			}
			if key.Name > query.AfterKey || (key.Name == query.AfterKey && v.CreatedOrder < cursor) {
				out = append(out, v)
			}
		}
		slices.SortFunc(out, func(a, b ObjectRecord) int {
			if n := cmp.Compare(a.Key.Name, b.Key.Name); n != 0 {
				return n
			}
			return cmp.Compare(b.CreatedOrder, a.CreatedOrder)
		})
		if len(out) > query.Limit {
			out = out[:query.Limit]
		}
		for i := range out {
			out[i] = cloneObject(out[i], false)
		}
		return nil
	})
	return out, err
}

func (r memoryReader) Objects(query ObjectQuery) ([]ObjectRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ObjectRecord{}
	if query.Limit <= 0 {
		return out, nil
	}
	err := r.repository.objects.View(r.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		current := map[string]ObjectRecord{}
		for key, v := range *state {
			if key.Bucket == query.Bucket && key.Name > query.After && strings.HasPrefix(key.Name, query.Prefix) && v.CreatedOrder > current[key.Name].CreatedOrder {
				current[key.Name] = v
			}
		}
		for _, v := range current {
			if !v.DeleteMarker {
				out = append(out, v)
			}
		}
		slices.SortFunc(out, func(a, b ObjectRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
		if len(out) > query.Limit {
			out = out[:query.Limit]
		}
		for i := range out {
			out[i] = cloneObject(out[i], false)
		}
		return nil
	})
	return out, err
}

func (r memoryReader) ObjectData(key ObjectVersionKey) ([][]byte, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	var out [][]byte
	err := r.repository.data.View(r.Context(), func(state *map[ObjectVersionKey][][]byte, _ *memory.Transaction) error {
		v, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		out = make([][]byte, len(v))
		for i := range v {
			out[i] = slices.Clone(v[i])
		}
		return nil
	})
	return out, err
}

func (w memoryWriter) PutBucket(v BucketRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if current, exists := (*w.state)[v.Key]; exists {
		v.Incarnation, v.CloudFormationOwner = current.Incarnation, current.CloudFormationOwner
	}
	if v.ACL == nil {
		v.ACL = DefaultACL(v.Key.Partition, v.AccountID)
	}
	(*w.state)[v.Key] = cloneBucket(v)
	return nil
}

func (w memoryWriter) DeleteBucket(key BucketKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(*w.state, key)
	if err := w.ReplaceBucketTags(key, nil); err != nil {
		return err
	}
	if err := w.ReplaceBucketCORS(key, nil); err != nil {
		return err
	}
	if err := w.ReplaceBucketWebsite(key, nil); err != nil {
		return err
	}
	if err := w.ReplaceBucketLogging(key, nil); err != nil {
		return err
	}
	if err := w.ReplaceBucketReplication(key, nil); err != nil {
		return err
	}
	if err := w.ReplaceBucketLifecycle(key, nil); err != nil {
		return err
	}
	if err := w.deleteBucketTiering(key); err != nil {
		return err
	}
	if err := w.deleteBucketMetrics(key); err != nil {
		return err
	}
	if err := w.deleteBucketInventory(key); err != nil {
		return err
	}
	if err := w.deleteBucketAnalytics(key); err != nil {
		return err
	}
	if err := w.ReplaceReplicationMetricSchedules(key, nil); err != nil {
		return err
	}
	if err := w.deleteReplicationWhere(func(source ObjectVersionKey) bool { return source.Bucket == key }); err != nil {
		return err
	}
	if err := w.repository.notifications.Update(w.Context(), func(state *map[BucketKey]NotificationState, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	}); err != nil {
		return err
	}
	if err := w.repository.objects.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		for object := range *state {
			if object.Bucket == key {
				delete(*state, object)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := w.repository.objectRestores.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRestore, _ *memory.Transaction) error {
		for object := range *state {
			if object.Bucket == key {
				delete(*state, object)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := w.repository.data.Update(w.Context(), func(state *map[ObjectVersionKey][][]byte, _ *memory.Transaction) error {
		for object := range *state {
			if object.Bucket == key {
				delete(*state, object)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := w.repository.objectTags.Update(w.Context(), func(state *map[ObjectVersionKey][]Tag, _ *memory.Transaction) error {
		for object := range *state {
			if object.Bucket == key {
				delete(*state, object)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := w.repository.objectParts.Update(w.Context(), func(state *map[ObjectVersionKey][]PartRecord, _ *memory.Transaction) error {
		for object := range *state {
			if object.Bucket == key {
				delete(*state, object)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := w.repository.uploads.Update(w.Context(), func(state *map[MultipartUploadKey]MultipartUploadRecord, _ *memory.Transaction) error {
		for upload := range *state {
			if upload.Bucket == key {
				delete(*state, upload)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return w.repository.uploadParts.Update(w.Context(), func(state *map[MultipartUploadKey]map[int32]memoryMultipartPart, _ *memory.Transaction) error {
		for upload := range *state {
			if upload.Bucket == key {
				delete(*state, upload)
			}
		}
		return nil
	})
}

func (w memoryWriter) PutObject(v ObjectRecord, data []byte) (int64, error) {
	if err := w.putObjectRecord(&v); err != nil {
		return 0, err
	}
	key := v.VersionKey()
	if err := w.ReplaceObjectTags(key, nil); err != nil {
		return 0, err
	}
	if err := w.repository.objectParts.Update(w.Context(), func(state *map[ObjectVersionKey][]PartRecord, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	}); err != nil {
		return 0, err
	}
	return v.Sequence, w.repository.data.Update(w.Context(), func(state *map[ObjectVersionKey][][]byte, _ *memory.Transaction) error {
		(*state)[key] = [][]byte{slices.Clone(data)}
		return nil
	})
}

// putObjectRecord publishes metadata without touching payload ownership.
func (w memoryWriter) putObjectRecord(v *ObjectRecord) error {
	return w.insertObjectRecord(v, true)
}

func (w memoryWriter) insertObjectRecord(v *ObjectRecord, allocateSequence bool) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	bucket, ok := (*w.state)[v.Key.Bucket]
	if !ok {
		return ErrNotFound
	}
	if v.ACL == nil {
		v.ACL = DefaultACL(v.Key.Bucket.Partition, bucket.AccountID)
	}
	if v.VersionID == "" {
		v.VersionID = "null"
	}
	key := v.VersionKey()
	if err := w.repository.objects.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		if _, exists := (*state)[key]; exists {
			if key.VersionID != "null" || !allocateSequence {
				return errors.New("S3 object version already exists")
			}
			if err := w.DeleteObjectRestore(key); err != nil {
				return err
			}
			if err := w.deleteReplicationWhere(func(source ObjectVersionKey) bool { return source == key }); err != nil {
				return err
			}
		}
		if allocateSequence {
			var err error
			v.Sequence, err = w.nextObjectSequence()
			if err != nil {
				return err
			}
			if v.CreatedOrder == 0 {
				v.CreatedOrder = v.Sequence
			}
		}
		(*state)[key] = cloneObject(*v, true)
		return nil
	}); err != nil {
		return err
	}
	return w.supersedeMultipartUploads(v.Key, v.CreatedOrder)
}

func (w memoryWriter) ReplaceObjectACL(key ObjectVersionKey, acl AccessControlList) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	return w.repository.objects.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		v, ok := (*state)[key]
		if !ok {
			return ErrNotFound
		}
		v.ACL = cloneACL(&acl)
		(*state)[key] = v
		return nil
	})
}

func (w memoryWriter) DeleteObject(key ObjectVersionKey) (int64, error) {
	if err := w.tx.Check(true); err != nil {
		return 0, err
	}
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	supersede := false
	if err := w.repository.objects.Update(w.Context(), func(state *map[ObjectVersionKey]ObjectRecord, _ *memory.Transaction) error {
		deleted, exists := (*state)[key]
		if exists {
			supersede = true
			for version, v := range *state {
				if version.ObjectKey == key.ObjectKey && v.CreatedOrder > deleted.CreatedOrder {
					supersede = false
					break
				}
			}
		} else if bucket, ok := (*w.state)[key.Bucket]; ok && bucket.Versioning == "" && key.VersionID == "null" {
			supersede = true
		}
		delete(*state, key)
		return nil
	}); err != nil {
		return 0, err
	}
	if err := w.DeleteObjectRestore(key); err != nil {
		return 0, err
	}
	if err := w.deleteReplicationWhere(func(source ObjectVersionKey) bool { return source == key }); err != nil {
		return 0, err
	}
	if err := w.repository.data.Update(w.Context(), func(state *map[ObjectVersionKey][][]byte, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	}); err != nil {
		return 0, err
	}
	if err := w.ReplaceObjectTags(key, nil); err != nil {
		return 0, err
	}
	if err := w.repository.objectParts.Update(w.Context(), func(state *map[ObjectVersionKey][]PartRecord, _ *memory.Transaction) error {
		delete(*state, key)
		return nil
	}); err != nil {
		return 0, err
	}
	if supersede {
		if err := w.supersedeMultipartUploads(key.ObjectKey, 0); err != nil {
			return 0, err
		}
	}
	return w.nextObjectSequence()
}

func (w memoryWriter) nextObjectSequence() (int64, error) {
	var next int64
	err := w.repository.sequence.Update(w.Context(), func(sequence *int64, _ *memory.Transaction) error {
		if *sequence == 1<<63-1 {
			return errors.New("S3 object sequence exhausted")
		}
		*sequence++
		next = *sequence
		return nil
	})
	return next, err
}

var _ Repository = (*MemoryRepository)(nil)
var _ Transaction = memoryWriter{}
