package memorydb

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/memorydb"
	"strings"
)

// TODO: Comeback provide AWS-managed physical at-rest protection and KMS-backed
// customer keys. Native AOF/RDB files are sensitive host data, not KMS ciphertext.
// TODO: Comeback implement MemoryDB's distributed durable log and multi-AZ HA;
// local native sharding, replication and AOF do not provide those cloud guarantees.
func (s *Service) createCluster(ctx context.Context, tx Transaction, in *api.CreateClusterRequest) (*api.CreateClusterResponse, error) {
	if e := s.ensureRuntime(); e != nil {
		return nil, e
	}
	k, e := keyFor(ctx, "cluster", value(in.ClusterName))
	if e != nil {
		return nil, e
	}
	if len(k.Name) > 40 {
		return nil, invalid("Cluster names cannot exceed 40 characters.")
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateCluster", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = tx.Cluster(k); e == nil {
		return nil, exists(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	if in.KmsKeyId != nil || in.SubnetGroupName != nil || len(in.SecurityGroupIds) > 0 || in.MultiRegionClusterName != nil || in.MaintenanceWindow != nil || in.SnsTopicArn != nil || len(in.SnapshotArns) > 0 || in.SnapshotWindow != nil || in.Port != nil || truth(in.AutoMinorVersionUpgrade) || truth(in.DataTiering) || (in.SnapshotRetentionLimit != nil && *in.SnapshotRetentionLimit != 0) {
		return nil, unsupported("KMS, VPC attachments, multi-region, maintenance, SNS, external snapshots, selected ports, automatic upgrades, tiering and automatic backups are not implemented.")
	}
	if (in.NetworkType != nil && value(in.NetworkType) != "ipv4") || (in.IpDiscovery != nil && value(in.IpDiscovery) != "ipv4") {
		return nil, unsupported("Only native IPv4 endpoints are supported.")
	}
	if value(in.NodeType) != "db.t4g.small" {
		return nil, unsupported("Only db.t4g.small is supported (local 1 GiB per node; not AWS CPU parity).")
	}
	eng := value(in.Engine)
	if eng == "" {
		eng = "redis"
	}
	if eng != "redis" && eng != "valkey" {
		return nil, invalid("Engine must be redis or valkey.")
	}
	version := engineVersion(eng)
	if in.EngineVersion != nil && value(in.EngineVersion) != version {
		return nil, unsupported("Only the pinned Valkey version or Redis 7.2 protocol compatibility is supported.")
	}
	v := Cluster{Key: k, RuntimeID: incarnation(), Status: "creating", Operation: "create", Description: value(in.Description), NodeType: value(in.NodeType), Engine: eng, EngineVersion: version, Shards: 1, Replicas: 1, TLSEnabled: true, Version: 1, Created: s.clock.Now(), Due: s.clock.Now(), Tags: tags}
	if in.NumShards != nil {
		v.Shards = int32(*in.NumShards)
	}
	if in.NumReplicasPerShard != nil {
		v.Replicas = int32(*in.NumReplicasPerShard)
	}
	if v.Shards < 1 || v.Shards > 16 || v.Replicas < 0 || v.Replicas > 5 || v.Shards*(v.Replicas+1) > 32 {
		return nil, invalid("Native local topology supports 1-16 shards, 0-5 replicas and at most 32 nodes.")
	}
	if in.TLSEnabled != nil {
		v.TLSEnabled = bool(*in.TLSEnabled)
	}
	a, e := s.loadACL(ctx, tx, "CreateCluster", value(in.ACLName))
	if e != nil {
		return nil, e
	}
	if a.Status != "active" {
		return nil, stateError("acl")
	}
	v.ACLName = a.Key.Name
	if !v.TLSEnabled && v.ACLName != "open-access" {
		return nil, invalid("Non-TLS clusters require the open-access ACL.")
	}
	v.ParameterGroup = "default." + engineFamily(eng)
	if in.ParameterGroupName != nil {
		p, e := s.loadParameterGroup(ctx, tx, "CreateCluster", value(in.ParameterGroupName))
		if e != nil {
			return nil, e
		}
		if p.Family != engineFamily(eng) {
			return nil, invalid("Parameter group engine family mismatch.")
		}
		v.ParameterGroup = p.Key.Name
	}
	if in.SnapshotName != nil {
		snap, e := s.loadSnapshot(ctx, tx, "CreateCluster", value(in.SnapshotName))
		if e != nil {
			return nil, e
		}
		if snap.Status != "available" {
			return nil, stateError("snapshot")
		}
		if in.NumShards == nil {
			v.Shards = snap.Shards
		}
		if in.NumReplicasPerShard == nil {
			v.Replicas = snap.Replicas
		}
		if snap.Shards != v.Shards || snap.Replicas != v.Replicas || snap.Engine != v.Engine {
			return nil, unsupported("Restore requires matching engine and snapshot topology.")
		}
		v.RestoreSnapshot = snap.RuntimeID
		v.Operation = "restore"
	}
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	return &api.CreateClusterResponse{Cluster: clusterDTO(v, true)}, nil
}
func (s *Service) describeClusters(ctx context.Context, tx Transaction, in *api.DescribeClustersRequest) (*api.DescribeClustersResponse, error) {
	out := &api.DescribeClustersResponse{}
	var rows []Cluster
	if in.ClusterName != nil {
		v, e := s.loadCluster(ctx, tx, "DescribeClusters", value(in.ClusterName))
		if e != nil {
			return nil, e
		}
		rows = []Cluster{v}
	} else {
		if e := s.authorize(ctx, "DescribeClusters", Key{}, nil, nil); e != nil {
			return nil, e
		}
		var e error
		rows, e = tx.Clusters(scopeFor(ctx))
		if e != nil {
			return nil, e
		}
	}
	rows, next, e := page(rows, in.MaxResults, in.NextToken, binding(ctx, "DescribeClusters", value(in.ClusterName)), func(v Cluster) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out.NextToken = next
	for _, v := range rows {
		out.Clusters = append(out.Clusters, *clusterDTO(v, truth(in.ShowShardDetails)))
	}
	return out, nil
}
func (s *Service) updateCluster(ctx context.Context, tx Transaction, in *api.UpdateClusterRequest) (*api.UpdateClusterResponse, error) {
	v, e := s.loadCluster(ctx, tx, "UpdateCluster", value(in.ClusterName))
	if e != nil {
		return nil, e
	}
	if v.Status != "available" {
		return nil, stateError("cluster")
	}
	if len(in.SecurityGroupIds) > 0 || in.MaintenanceWindow != nil || in.SnsTopicArn != nil || in.SnsTopicStatus != nil || in.SnapshotWindow != nil || (in.SnapshotRetentionLimit != nil && *in.SnapshotRetentionLimit != 0) || (in.IpDiscovery != nil && value(in.IpDiscovery) != "ipv4") || (in.NodeType != nil && value(in.NodeType) != v.NodeType) || (in.Engine != nil && value(in.Engine) != v.Engine) || (in.EngineVersion != nil && value(in.EngineVersion) != v.EngineVersion) || in.ReplicaConfiguration != nil || in.ShardConfiguration != nil {
		return nil, unsupported("Network, maintenance, notification, backup, engine and topology modifications are not implemented.")
	}
	if in.Description != nil {
		v.Description = value(in.Description)
	}
	if in.ACLName != nil {
		a, e := s.loadACL(ctx, tx, "UpdateCluster", value(in.ACLName))
		if e != nil {
			return nil, e
		}
		if a.Status != "active" {
			return nil, stateError("acl")
		}
		if !v.TLSEnabled && a.Key.Name != "open-access" {
			return nil, invalid("Non-TLS clusters require open-access ACL.")
		}
		v.ACLName = a.Key.Name
	}
	if in.ParameterGroupName != nil {
		p, e := s.loadParameterGroup(ctx, tx, "UpdateCluster", value(in.ParameterGroupName))
		if e != nil {
			return nil, e
		}
		if p.Family != engineFamily(v.Engine) {
			return nil, invalid("Parameter group family mismatch.")
		}
		v.ParameterGroup = p.Key.Name
	}
	s.scheduleCluster(&v, "update")
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	return &api.UpdateClusterResponse{Cluster: clusterDTO(v, true)}, nil
}
func (s *Service) deleteCluster(ctx context.Context, tx Transaction, in *api.DeleteClusterRequest) (*api.DeleteClusterResponse, error) {
	v, e := s.loadCluster(ctx, tx, "DeleteCluster", value(in.ClusterName))
	if e != nil {
		return nil, e
	}
	if in.MultiRegionClusterName != nil {
		return nil, unsupported("Multi-region clusters are not implemented.")
	}
	if v.Status == "deleting" || v.Status == "creating" || v.Status == "modifying" {
		return nil, stateError("cluster")
	}
	snapshots, e := tx.Snapshots(v.Key.Scope)
	if e != nil {
		return nil, e
	}
	for _, snap := range snapshots {
		if snap.SourceRuntimeID == v.RuntimeID && snap.Status != "available" && snap.Operation != "delete" {
			return nil, stateError("cluster")
		}
	}
	if in.FinalSnapshotName != nil {
		if _, e = s.admitSnapshot(ctx, tx, v, value(in.FinalSnapshotName), nil); e != nil {
			return nil, e
		}
	}
	s.scheduleCluster(&v, "delete")
	v.Status = "deleting"
	if e = tx.PutCluster(v); e != nil {
		return nil, e
	}
	return &api.DeleteClusterResponse{Cluster: clusterDTO(v, true)}, nil
}
func (s *Service) scheduleCluster(v *Cluster, operation string) {
	v.Operation = operation
	v.Status = "modifying"
	v.Version++
	v.Due = s.clock.Now()
}
func (s *Service) describeEngineVersions(ctx context.Context, _ Transaction, in *api.DescribeEngineVersionsRequest) (*api.DescribeEngineVersionsResponse, error) {
	if e := s.authorize(ctx, "DescribeEngineVersions", Key{}, nil, nil); e != nil {
		return nil, e
	}
	rows := []api.EngineVersionInfo{}
	for _, eng := range []string{"redis", "valkey"} {
		if in.Engine != nil && value(in.Engine) != eng {
			continue
		}
		if in.EngineVersion != nil && value(in.EngineVersion) != engineVersion(eng) {
			continue
		}
		if in.ParameterGroupFamily != nil && value(in.ParameterGroupFamily) != engineFamily(eng) {
			continue
		}
		rows = append(rows, api.EngineVersionInfo{Engine: new(api.String(eng)), EngineVersion: new(api.String(engineVersion(eng))), ParameterGroupFamily: new(api.String(engineFamily(eng)))})
	}
	rows, next, e := page(rows, in.MaxResults, in.NextToken, binding(ctx, "DescribeEngineVersions", strings.Join([]string{value(in.Engine), value(in.EngineVersion), value(in.ParameterGroupFamily)}, ":")), func(v api.EngineVersionInfo) string { return value(v.Engine) })
	if e != nil {
		return nil, e
	}
	return &api.DescribeEngineVersionsResponse{EngineVersions: rows, NextToken: next}, nil
}
