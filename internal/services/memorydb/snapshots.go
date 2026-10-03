package memorydb

import (
	"context"
	"errors"
	"fmt"
	api "stackd/internal/awsapi/memorydb"
)

func (s *Service) loadSnapshot(ctx context.Context, r Reader, action, name string) (Snapshot, error) {
	k, e := keyFor(ctx, "snapshot", name)
	if e != nil {
		return Snapshot{}, e
	}
	v, e := r.Snapshot(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(k.Kind)
	}
	if e != nil {
		return v, e
	}
	if action == "CreateCluster" {
		return v, nil
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func snapshotDTO(v Snapshot, detail bool) *api.Snapshot {
	out := &api.Snapshot{Name: new(api.String(v.Key.Name)), ARN: new(api.String(v.Key.ARN())), Status: new(api.String(v.Status)), Source: new(api.String("manual")), ClusterConfiguration: &api.ClusterConfiguration{Name: new(api.String(v.Source)), Engine: new(api.String(v.Engine)), EngineVersion: new(api.String(v.EngineVersion)), NodeType: new(api.String(v.NodeType)), NumShards: new(api.IntegerOptional(v.Shards)), ParameterGroupName: new(api.String(v.ParameterGroup))}}
	if detail {
		for i := int32(0); i < v.Shards; i++ {
			out.ClusterConfiguration.Shards = append(out.ClusterConfiguration.Shards, api.ShardDetail{Name: new(api.String(fmt.Sprintf("%04d", i+1))), SnapshotCreationTime: new(api.TStamp(v.Created)), Configuration: &api.ShardConfiguration{ReplicaCount: new(api.IntegerOptional(v.Replicas)), Slots: new(api.String(fmt.Sprintf("%d-%d", 16384*i/v.Shards, 16384*(i+1)/v.Shards-1)))}})
		}
	}
	return out
}
func (s *Service) admitSnapshot(ctx context.Context, tx Transaction, c Cluster, name string, tags map[string]string) (Snapshot, error) {
	k, e := keyFor(ctx, "snapshot", name)
	if e != nil {
		return Snapshot{}, e
	}
	if e = s.authorize(ctx, "CreateSnapshot", k, nil, tags); e != nil {
		return Snapshot{}, e
	}
	if _, e = tx.Snapshot(k); e == nil {
		return Snapshot{}, exists(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return Snapshot{}, e
	}
	if c.Status != "available" {
		return Snapshot{}, stateError("cluster")
	}
	v := Snapshot{Key: k, RuntimeID: incarnation(), SourceRuntimeID: c.RuntimeID, Source: c.Key.Name, Engine: c.Engine, EngineVersion: c.EngineVersion, NodeType: c.NodeType, ParameterGroup: c.ParameterGroup, ACLName: c.ACLName, Shards: c.Shards, Replicas: c.Replicas, TLSEnabled: c.TLSEnabled, Status: "creating", Operation: "snapshot", Version: 1, Created: s.clock.Now(), Due: s.clock.Now(), Tags: tags}
	return v, tx.PutSnapshot(v)
}
func (s *Service) createSnapshot(ctx context.Context, tx Transaction, in *api.CreateSnapshotRequest) (*api.CreateSnapshotResponse, error) {
	if e := s.ensureRuntime(); e != nil {
		return nil, e
	}
	if in.KmsKeyId != nil {
		return nil, unsupported("KMS snapshot encryption is not implemented.")
	}
	c, e := s.loadCluster(ctx, tx, "CreateSnapshot", value(in.ClusterName))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	v, e := s.admitSnapshot(ctx, tx, c, value(in.SnapshotName), tags)
	if e != nil {
		return nil, e
	}
	return &api.CreateSnapshotResponse{Snapshot: snapshotDTO(v, true)}, nil
}
func (s *Service) copySnapshot(ctx context.Context, tx Transaction, in *api.CopySnapshotRequest) (*api.CopySnapshotResponse, error) {
	if e := s.ensureRuntime(); e != nil {
		return nil, e
	}
	if in.TargetBucket != nil || in.KmsKeyId != nil {
		return nil, unsupported("S3 snapshot export and KMS encryption are not implemented.")
	}
	source, e := s.loadSnapshot(ctx, tx, "CopySnapshot", value(in.SourceSnapshotName))
	if e != nil {
		return nil, e
	}
	if source.Status != "available" {
		return nil, stateError("snapshot")
	}
	k, e := keyFor(ctx, "snapshot", value(in.TargetSnapshotName))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CopySnapshot", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = tx.Snapshot(k); e == nil {
		return nil, exists("snapshot")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	v := source
	v.Key = k
	v.CopySource = source.RuntimeID
	v.RuntimeID = incarnation()
	v.Operation = "copy"
	v.Status = "creating"
	v.Version = 1
	v.Created = s.clock.Now()
	v.Due = s.clock.Now()
	v.Tags = tags
	if e = tx.PutSnapshot(v); e != nil {
		return nil, e
	}
	return &api.CopySnapshotResponse{Snapshot: snapshotDTO(v, true)}, nil
}
func (s *Service) deleteSnapshot(ctx context.Context, tx Transaction, in *api.DeleteSnapshotRequest) (*api.DeleteSnapshotResponse, error) {
	v, e := s.loadSnapshot(ctx, tx, "DeleteSnapshot", value(in.SnapshotName))
	if e != nil {
		return nil, e
	}
	if v.Status != "available" && v.Status != "failed" {
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
	for _, other := range snapshots {
		if other.CopySource == v.RuntimeID {
			return nil, stateError("snapshot")
		}
	}
	v.Status = "deleting"
	v.Operation = "delete"
	v.Due = s.clock.Now()
	v.Version++
	if e = tx.PutSnapshot(v); e != nil {
		return nil, e
	}
	return &api.DeleteSnapshotResponse{Snapshot: snapshotDTO(v, true)}, nil
}
func (s *Service) describeSnapshots(ctx context.Context, tx Transaction, in *api.DescribeSnapshotsRequest) (*api.DescribeSnapshotsResponse, error) {
	if in.Source != nil && value(in.Source) != "manual" && value(in.Source) != "automated" {
		return nil, invalid("Source must be manual or automated.")
	}
	var rows []Snapshot
	if in.SnapshotName != nil {
		v, e := s.loadSnapshot(ctx, tx, "DescribeSnapshots", value(in.SnapshotName))
		if e != nil {
			return nil, e
		}
		rows = []Snapshot{v}
	} else {
		if e := s.authorize(ctx, "DescribeSnapshots", Key{}, nil, nil); e != nil {
			return nil, e
		}
		var e error
		rows, e = tx.Snapshots(scopeFor(ctx))
		if e != nil {
			return nil, e
		}
	}
	filtered := rows[:0]
	for _, v := range rows {
		if value(in.Source) == "automated" || (in.ClusterName != nil && v.Source != value(in.ClusterName)) {
			continue
		}
		filtered = append(filtered, v)
	}
	rows, next, e := page(filtered, in.MaxResults, in.NextToken, binding(ctx, "DescribeSnapshots", value(in.SnapshotName)+":"+value(in.ClusterName)+":"+value(in.Source)), func(v Snapshot) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.DescribeSnapshotsResponse{NextToken: next}
	for _, v := range rows {
		out.Snapshots = append(out.Snapshots, *snapshotDTO(v, truth(in.ShowDetail)))
	}
	return out, nil
}
