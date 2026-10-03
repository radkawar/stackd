package elasticache

import (
	"context"
	"errors"
	"fmt"
	"maps"
	api "stackd/internal/awsapi/elasticache"
	"time"
)

func (s *Service) loadSnapshot(ctx context.Context, r Reader, action, name string) (Snapshot, error) {
	k, e := resourceKey(ctx, "snapshot", name)
	if e != nil {
		return Snapshot{}, e
	}
	v, e := r.Snapshot(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound("snapshot")
	}
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func (s *Service) admitSnapshot(ctx context.Context, tx Transaction, source Cluster, name string, tags api.TagList) (Snapshot, error) {
	if source.Status != "available" {
		return Snapshot{}, stateError(source.Key.Kind)
	}
	k, e := resourceKey(ctx, "snapshot", name)
	if e != nil {
		return Snapshot{}, e
	}
	tagMap, e := tagsFrom(tags)
	if e != nil {
		return Snapshot{}, e
	}
	if e = s.authorize(ctx, "CreateSnapshot", k, nil, tagMap); e != nil {
		return Snapshot{}, e
	}
	if _, e = tx.Snapshot(k); e == nil {
		return Snapshot{}, existsError("snapshot")
	} else if !errors.Is(e, ErrNotFound) {
		return Snapshot{}, e
	}
	v := Snapshot{Key: k, SourceKind: source.Key.Kind, Source: source.Key.Name, SourceRuntimeID: source.RuntimeID, RuntimeID: newRuntimeID(), Engine: source.Engine, EngineVersion: source.EngineVersion, NodeType: source.NodeType, Shards: source.Shards, Replicas: source.Replicas, ClusterMode: source.ClusterMode, TLSEnabled: source.TLSEnabled, MemoryBytes: source.MemoryBytes, Parameters: maps.Clone(source.Parameters), Status: "creating", Operation: "snapshot", Version: 1, Created: s.clock.Now(), Due: s.clock.Now(), Tags: tagMap}
	if e = tx.PutSnapshot(v); e != nil {
		return v, e
	}
	source.Status = "snapshotting"
	source.Due = time.Time{}
	source.Operation = ""
	source.Version++
	return v, tx.PutCluster(source)
}
func (s *Service) createSnapshot(ctx context.Context, tx Transaction, in *api.CreateSnapshotMessage) (*api.CreateSnapshotResult, error) {
	if in.KmsKeyId != nil {
		return nil, unsupported("KMS snapshot encryption is not supported.")
	}
	kind, name := "cluster", value(in.CacheClusterId)
	if in.ReplicationGroupId != nil {
		if in.CacheClusterId != nil {
			return nil, unsupported("Specify only one snapshot source.")
		}
		kind, name = "replicationgroup", value(in.ReplicationGroupId)
	}
	source, e := s.loadCluster(ctx, tx, "CreateSnapshot", kind, name)
	if e != nil {
		return nil, e
	}
	v, e := s.admitSnapshot(ctx, tx, source, value(in.SnapshotName), in.Tags)
	if e != nil {
		return nil, e
	}
	return &api.CreateSnapshotResult{Snapshot: snapshotOutput(v, true)}, nil
}
func (s *Service) copySnapshot(ctx context.Context, tx Transaction, in *api.CopySnapshotMessage) (*api.CopySnapshotResult, error) {
	if in.KmsKeyId != nil || in.TargetBucket != nil {
		return nil, unsupported("Cross-service export and KMS snapshot encryption are not supported.")
	}
	v, e := s.loadSnapshot(ctx, tx, "CopySnapshot", value(in.SourceSnapshotName))
	if e != nil {
		return nil, e
	}
	if v.Status != "available" {
		return nil, stateError("snapshot")
	}
	k, e := resourceKey(ctx, "snapshot", value(in.TargetSnapshotName))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if in.Tags == nil {
		tags = maps.Clone(v.Tags)
	}
	if e = s.authorize(ctx, "CopySnapshot", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = tx.Snapshot(k); e == nil {
		return nil, existsError("snapshot")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	v.Key = k
	v.CopySource = v.RuntimeID
	v.RuntimeID = newRuntimeID()
	v.Status = "creating"
	v.Operation = "copy"
	v.Created = s.clock.Now()
	v.Due = v.Created
	v.Version = 1
	v.Tags = tags
	return &api.CopySnapshotResult{Snapshot: snapshotOutput(v, true)}, tx.PutSnapshot(v)
}
func (s *Service) deleteSnapshot(ctx context.Context, tx Transaction, in *api.DeleteSnapshotMessage) (*api.DeleteSnapshotResult, error) {
	v, e := s.loadSnapshot(ctx, tx, "DeleteSnapshot", value(in.SnapshotName))
	if e != nil {
		return nil, e
	}
	if v.Status != "available" {
		return nil, stateError("snapshot")
	}
	clusters, e := tx.Clusters(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	for _, c := range clusters {
		if c.RestoreSnapshot == v.RuntimeID {
			return nil, stateError("snapshot")
		}
	}
	snapshots, e := tx.Snapshots(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	for _, snap := range snapshots {
		if snap.CopySource == v.RuntimeID {
			return nil, stateError("snapshot")
		}
	}
	v.Status = "deleting"
	v.Operation = "delete"
	v.Version++
	v.Due = s.clock.Now()
	return &api.DeleteSnapshotResult{Snapshot: snapshotOutput(v, true)}, tx.PutSnapshot(v)
}
func snapshotOutput(v Snapshot, showConfig bool) *api.Snapshot {
	out := &api.Snapshot{ARN: new(api.String(v.Key.ARN())), SnapshotName: new(api.String(v.Key.Name)), SnapshotStatus: new(api.String(v.Status)), SnapshotSource: new(api.String("manual")), Engine: new(api.String(v.Engine)), EngineVersion: new(api.String(v.EngineVersion)), CacheNodeType: new(api.String(v.NodeType)), NumNodeGroups: new(api.IntegerOptional(v.Shards)), NumCacheNodes: new(api.IntegerOptional(v.Shards * (v.Replicas + 1)))}
	if v.SourceKind == "replicationgroup" {
		out.ReplicationGroupId = new(api.String(v.Source))
	} else {
		out.CacheClusterId = new(api.String(v.Source))
	}
	for shard := int32(0); shard < v.Shards; shard++ {
		node := api.NodeSnapshot{NodeGroupId: new(api.String(fmt.Sprintf("%04d", shard+1))), CacheNodeId: new(api.String("0001")), SnapshotCreateTime: new(v.Created)}
		if showConfig {
			node.NodeGroupConfiguration = &api.NodeGroupConfiguration{NodeGroupId: new(api.AllowedNodeGroupId(fmt.Sprintf("%04d", shard+1))), ReplicaCount: new(api.IntegerOptional(v.Replicas))}
			if v.ClusterMode {
				node.NodeGroupConfiguration.Slots = new(api.String(fmt.Sprintf("%d-%d", 16384*shard/v.Shards, 16384*(shard+1)/v.Shards-1)))
			}
		}
		out.NodeSnapshots = append(out.NodeSnapshots, node)
	}
	return out
}
func (s *Service) describeSnapshots(ctx context.Context, tx Transaction, in *api.DescribeSnapshotsMessage) (*api.DescribeSnapshotsListMessage, error) {
	source := value(in.SnapshotSource)
	if source != "" && source != "manual" && source != "automated" {
		return nil, failure("InvalidParameterValue", "SnapshotSource must be manual or automated.")
	}
	if in.CacheClusterId != nil && in.ReplicationGroupId != nil {
		return nil, unsupported("Specify only one snapshot source.")
	}
	var all []Snapshot
	var e error
	if in.SnapshotName != nil {
		v, err := s.loadSnapshot(ctx, tx, "DescribeSnapshots", value(in.SnapshotName))
		e = err
		all = []Snapshot{v}
	} else {
		e = s.authorize(ctx, "DescribeSnapshots", Key{}, nil, nil)
		if e == nil {
			all, e = tx.Snapshots(scopeFor(ctx))
		}
	}
	if e != nil {
		return nil, e
	}
	filtered := all[:0]
	for _, v := range all {
		if source == "automated" {
			continue
		}
		if in.CacheClusterId != nil && (v.SourceKind != "cluster" || v.Source != value(in.CacheClusterId)) {
			continue
		}
		if in.ReplicationGroupId != nil && (v.SourceKind != "replicationgroup" || v.Source != value(in.ReplicationGroupId)) {
			continue
		}
		filtered = append(filtered, v)
	}
	selected, next, e := page(ctx, "DescribeSnapshots", value(in.SnapshotName)+"/"+source+"/"+value(in.CacheClusterId)+"/"+value(in.ReplicationGroupId), filtered, in.Marker, in.MaxRecords, func(v Snapshot) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.DescribeSnapshotsListMessage{Marker: next}
	for _, v := range selected {
		out.Snapshots = append(out.Snapshots, *snapshotOutput(v, boolean(in.ShowNodeGroupConfig)))
	}
	return out, nil
}
