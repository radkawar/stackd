package elasticache

import (
	"context"
	"errors"
	"maps"
	engine "stackd/engine/valkey"
	api "stackd/internal/awsapi/elasticache"
	"strings"
	"time"
)

func (s *Service) prepareCluster(ctx context.Context, tx Transaction, v Cluster, tags api.TagList, snapshot, token string) (Cluster, error) {
	if e := s.requireRuntime(); e != nil {
		return v, e
	}
	var e error
	v.Engine, v.EngineVersion, e = engineVersion(v.Engine, v.EngineVersion)
	if e != nil {
		return v, e
	}
	if v.NodeType == "" {
		return v, failure("InvalidParameterValue", "CacheNodeType is required.")
	}
	v.MemoryBytes, e = nodeMemory(v.NodeType)
	if e != nil {
		return v, e
	}
	v.Tags, e = tagsFrom(tags)
	if e != nil {
		return v, e
	}
	action := "CreateCacheCluster"
	if v.Key.Kind == "replicationgroup" {
		action = "CreateReplicationGroup"
	}
	if e = s.authorize(ctx, action, v.Key, nil, v.Tags); e != nil {
		return v, e
	}
	if _, e = tx.Cluster(v.Key); e == nil {
		return v, existsError(v.Key.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return v, e
	}
	existing, e := tx.Clusters(v.Key.Scope)
	if e != nil {
		return v, e
	}
	for _, other := range existing {
		if (v.Key.Kind == "cluster" && ownsMember(other, v.Key.Name)) ||
			(other.Key.Kind == "cluster" && ownsMember(v, other.Key.Name)) {
			return v, existsError("cluster")
		}
	}
	if token != "" {
		if !v.TLSEnabled {
			return v, unsupported("AuthToken requires TransitEncryptionEnabled.")
		}
		h, e := tokenHash(token)
		if e != nil {
			return v, e
		}
		v.AuthHashes = []string{h}
	}
	if v.UserGroup != "" {
		if !v.TLSEnabled {
			return v, unsupported("User groups require transit encryption.")
		}
		if token != "" {
			return v, unsupported("AuthToken and UserGroupIds cannot be combined.")
		}
		if e = s.validateAttachment(ctx, tx, action, v); e != nil {
			return v, e
		}
	}
	v.Parameters, e = s.clusterParameters(ctx, tx, action, v)
	if e != nil {
		return v, e
	}
	if snapshot != "" {
		k, e := resourceKey(ctx, "snapshot", snapshot)
		if e != nil {
			return v, e
		}
		snap, e := tx.Snapshot(k)
		if errors.Is(e, ErrNotFound) {
			return v, notFound("snapshot")
		}
		if e != nil {
			return v, e
		}
		if e = s.authorize(ctx, action, k, snap.Tags, nil); e != nil {
			return v, e
		}
		if snap.Status != "available" {
			return v, stateError("snapshot")
		}
		if snap.Shards != v.Shards || snap.Replicas != v.Replicas || snap.ClusterMode != v.ClusterMode || snap.Engine != v.Engine {
			return v, unsupported("Restore requires matching engine and topology.")
		}
		v.RestoreSnapshot = snap.RuntimeID
	}
	v.RuntimeID = newRuntimeID()
	v.Status = "creating"
	v.Operation = "create"
	v.Created = s.clock.Now()
	v.Due = v.Created
	v.Version = 1
	return v, tx.PutCluster(v)
}
func (s *Service) createCluster(ctx context.Context, tx Transaction, in *api.CreateCacheClusterMessage) (*api.CreateCacheClusterResult, error) {
	if e := validateCreateCacheClusterMessage(in); e != nil {
		return nil, e
	}
	if integer(in.NumCacheNodes, 1) != 1 {
		return nil, unsupported("Valkey cache clusters require exactly one node; use a replication group for replicas.")
	}
	k, e := resourceKey(ctx, "cluster", value(in.CacheClusterId))
	if e != nil {
		return nil, e
	}
	v, e := s.prepareCluster(ctx, tx, Cluster{Key: k, Engine: value(in.Engine), EngineVersion: value(in.EngineVersion), NodeType: value(in.CacheNodeType), ParameterGroup: value(in.CacheParameterGroupName), Shards: 1, TLSEnabled: boolean(in.TransitEncryptionEnabled)}, in.Tags, value(in.SnapshotName), value(in.AuthToken))
	if e != nil {
		return nil, e
	}
	return &api.CreateCacheClusterResult{CacheCluster: clusterOutput(v, true)}, nil
}
func (s *Service) createReplicationGroup(ctx context.Context, tx Transaction, in *api.CreateReplicationGroupMessage) (*api.CreateReplicationGroupResult, error) {
	if e := validateCreateReplicationGroupMessage(in); e != nil {
		return nil, e
	}
	k, e := resourceKey(ctx, "replicationgroup", value(in.ReplicationGroupId))
	if e != nil {
		return nil, e
	}
	if value(in.ReplicationGroupDescription) == "" {
		return nil, failure("InvalidParameterValue", "ReplicationGroupDescription is required.")
	}
	mode := value(in.ClusterMode)
	clustered := mode == "enabled" || strings.HasSuffix(value(in.CacheParameterGroupName), ".cluster.on")
	if mode != "" && mode != "enabled" && mode != "disabled" {
		return nil, unsupported("Only enabled and disabled cluster modes are supported.")
	}
	if mode == "disabled" && clustered {
		return nil, unsupported("ClusterMode conflicts with the parameter group.")
	}
	shards := integer(in.NumNodeGroups, 1)
	if shards > 1 {
		if mode == "disabled" {
			return nil, unsupported("Multiple shards require cluster mode.")
		}
		clustered = true
	}
	replicas := integer(in.ReplicasPerNodeGroup, 0)
	if in.NumCacheClusters != nil {
		if in.ReplicasPerNodeGroup != nil || shards != 1 {
			return nil, unsupported("NumCacheClusters cannot be combined with shard replication settings.")
		}
		replicas = int32(*in.NumCacheClusters) - 1
	}
	if shards < 1 || shards > 16 || replicas < 0 || replicas > 5 || shards*(replicas+1) > 32 {
		return nil, unsupported("The local native topology supports at most 16 shards and 32 total nodes.")
	}
	// TODO: Comeback provide AWS automatic failover coordination and Multi-AZ
	// placement; native shard replicas alone do not establish either guarantee.
	if boolean(in.AutomaticFailoverEnabled) {
		return nil, unsupported("AutomaticFailoverEnabled requires an unavailable native coordinator.")
	}
	if len(in.UserGroupIds) > 1 {
		return nil, failure("InvalidParameterValue", "At most one user group can be attached.")
	}
	group := ""
	if len(in.UserGroupIds) == 1 {
		group = string(in.UserGroupIds[0])
	}
	if in.TransitEncryptionMode != nil && value(in.TransitEncryptionMode) != "required" {
		return nil, unsupported("Only required transit encryption mode is supported.")
	}
	if in.TransitEncryptionMode != nil && !boolean(in.TransitEncryptionEnabled) {
		return nil, unsupported("TransitEncryptionMode requires transit encryption.")
	}
	v, e := s.prepareCluster(ctx, tx, Cluster{Key: k, Engine: value(in.Engine), EngineVersion: value(in.EngineVersion), NodeType: value(in.CacheNodeType), Description: value(in.ReplicationGroupDescription), ParameterGroup: value(in.CacheParameterGroupName), UserGroup: group, Shards: shards, Replicas: replicas, ClusterMode: clustered, TLSEnabled: boolean(in.TransitEncryptionEnabled)}, in.Tags, value(in.SnapshotName), value(in.AuthToken))
	if e != nil {
		return nil, e
	}
	return &api.CreateReplicationGroupResult{ReplicationGroup: replicationOutput(v)}, nil
}
func (s *Service) markCluster(tx Transaction, v Cluster, operation, status string) error {
	v.Operation = operation
	v.Status = status
	v.Version++
	v.Due = s.clock.Now()
	return tx.PutCluster(v)
}
func (s *Service) modifyCluster(ctx context.Context, tx Transaction, in *api.ModifyCacheClusterMessage) (*api.ModifyCacheClusterResult, error) {
	if e := validateModifyCacheClusterMessage(in); e != nil {
		return nil, e
	}
	v, e := s.loadCluster(ctx, tx, "ModifyCacheCluster", "cluster", value(in.CacheClusterId))
	if e != nil {
		return nil, e
	}
	if v.Status != "available" {
		return nil, stateError(v.Key.Kind)
	}
	if !boolean(in.ApplyImmediately) {
		return nil, unsupported("Native modifications require ApplyImmediately; maintenance scheduling is unavailable.")
	}
	if in.CacheParameterGroupName != nil {
		v.ParameterGroup = value(in.CacheParameterGroupName)
		v.Parameters, e = s.clusterParameters(ctx, tx, "ModifyCacheCluster", v)
		if e != nil {
			return nil, e
		}
	}
	if e = updateAuth(&v, in.AuthToken, in.AuthTokenUpdateStrategy); e != nil {
		return nil, e
	}
	e = s.markCluster(tx, v, "modify", "modifying")
	v.Status = "modifying"
	return &api.ModifyCacheClusterResult{CacheCluster: clusterOutput(v, true)}, e
}
func (s *Service) modifyReplicationGroup(ctx context.Context, tx Transaction, in *api.ModifyReplicationGroupMessage) (*api.ModifyReplicationGroupResult, error) {
	if e := validateModifyReplicationGroupMessage(in); e != nil {
		return nil, e
	}
	v, e := s.loadCluster(ctx, tx, "ModifyReplicationGroup", "replicationgroup", value(in.ReplicationGroupId))
	if e != nil {
		return nil, e
	}
	if v.Status != "available" {
		return nil, stateError(v.Key.Kind)
	}
	if !boolean(in.ApplyImmediately) {
		return nil, unsupported("Native modifications require ApplyImmediately.")
	}
	if in.ReplicationGroupDescription != nil {
		if value(in.ReplicationGroupDescription) == "" {
			return nil, failure("InvalidParameterValue", "Description must not be empty.")
		}
		v.Description = value(in.ReplicationGroupDescription)
	}
	if in.CacheParameterGroupName != nil {
		v.ParameterGroup = value(in.CacheParameterGroupName)
		v.Parameters, e = s.clusterParameters(ctx, tx, "ModifyReplicationGroup", v)
		if e != nil {
			return nil, e
		}
	}
	if boolean(in.RemoveUserGroups) {
		if len(in.UserGroupIdsToAdd) > 0 || len(in.UserGroupIdsToRemove) > 0 {
			return nil, unsupported("RemoveUserGroups cannot be combined with user group lists.")
		}
		v.UserGroup = ""
	}
	for _, id := range in.UserGroupIdsToRemove {
		if string(id) != v.UserGroup {
			return nil, notFound("usergroup")
		}
		v.UserGroup = ""
	}
	if len(in.UserGroupIdsToAdd) > 1 {
		return nil, unsupported("At most one user group is supported.")
	}
	for _, id := range in.UserGroupIdsToAdd {
		if v.UserGroup != "" {
			return nil, unsupported("Remove the existing user group before adding another.")
		}
		v.UserGroup = string(id)
	}
	if e = updateAuth(&v, in.AuthToken, in.AuthTokenUpdateStrategy); e != nil {
		return nil, e
	}
	if v.UserGroup != "" {
		if !v.TLSEnabled || len(v.AuthHashes) > 0 {
			return nil, unsupported("User groups require TLS and cannot coexist with AUTH tokens.")
		}
		if e = s.validateAttachment(ctx, tx, "ModifyReplicationGroup", v); e != nil {
			return nil, e
		}
	}
	e = s.markCluster(tx, v, "modify", "modifying")
	v.Status = "modifying"
	return &api.ModifyReplicationGroupResult{ReplicationGroup: replicationOutput(v)}, e
}
func updateAuth(v *Cluster, token *api.String, strategy *api.AuthTokenUpdateStrategyType) error {
	if token == nil && strategy == nil {
		return nil
	}
	if !v.TLSEnabled {
		return unsupported("AUTH tokens require transit encryption.")
	}
	mode := value(strategy)
	if mode == "" {
		mode = "ROTATE"
	}
	switch mode {
	case "DELETE":
		if token != nil {
			return unsupported("DELETE must not include AuthToken.")
		}
		v.AuthHashes = nil
	case "SET", "ROTATE":
		h, e := tokenHash(value(token))
		if e != nil {
			return e
		}
		if mode == "SET" {
			v.AuthHashes = []string{h}
		} else {
			if len(v.AuthHashes) == 0 {
				return unsupported("Initial AUTH token requires SET; unauthenticated rotation is not supported.")
			}
			v.AuthHashes = []string{v.AuthHashes[len(v.AuthHashes)-1], h}
		}
	default:
		return failure("InvalidParameterValue", "Invalid AuthTokenUpdateStrategy.")
	}
	return nil
}
func (s *Service) deleteCluster(ctx context.Context, tx Transaction, in *api.DeleteCacheClusterMessage) (*api.DeleteCacheClusterResult, error) {
	v, e := s.loadCluster(ctx, tx, "DeleteCacheCluster", "cluster", value(in.CacheClusterId))
	if e != nil {
		return nil, e
	}
	e = s.beginDelete(ctx, tx, v, value(in.FinalSnapshotIdentifier))
	v.Status = "deleting"
	return &api.DeleteCacheClusterResult{CacheCluster: clusterOutput(v, true)}, e
}
func (s *Service) deleteReplicationGroup(ctx context.Context, tx Transaction, in *api.DeleteReplicationGroupMessage) (*api.DeleteReplicationGroupResult, error) {
	if boolean(in.RetainPrimaryCluster) {
		return nil, unsupported("Retaining a primary requires native ownership transfer, which is not supported.")
	}
	v, e := s.loadCluster(ctx, tx, "DeleteReplicationGroup", "replicationgroup", value(in.ReplicationGroupId))
	if e != nil {
		return nil, e
	}
	e = s.beginDelete(ctx, tx, v, value(in.FinalSnapshotIdentifier))
	v.Status = "deleting"
	return &api.DeleteReplicationGroupResult{ReplicationGroup: replicationOutput(v)}, e
}
func (s *Service) beginDelete(ctx context.Context, tx Transaction, v Cluster, final string) error {
	if v.Status != "available" && v.Status != "create-failed" {
		return stateError(v.Key.Kind)
	}
	snapshots, e := tx.Snapshots(v.Key.Scope)
	if e != nil {
		return e
	}
	for _, snap := range snapshots {
		if snap.SourceRuntimeID == v.RuntimeID && snap.Status != "available" {
			return stateError("snapshot")
		}
	}
	if final != "" {
		if _, e = s.admitSnapshot(ctx, tx, v, final, nil); e != nil {
			return e
		}
		v.Operation = "delete-after-snapshot"
		v.Status = "deleting"
		v.Version++
		v.Due = s.clock.Now().Add(time.Second)
		return tx.PutCluster(v)
	}
	return s.markCluster(tx, v, "delete", "deleting")
}
func (s *Service) rebootCluster(ctx context.Context, tx Transaction, in *api.RebootCacheClusterMessage) (*api.RebootCacheClusterResult, error) {
	v, e := s.loadCluster(ctx, tx, "RebootCacheCluster", "cluster", value(in.CacheClusterId))
	if e != nil {
		return nil, e
	}
	if v.Status != "available" {
		return nil, stateError(v.Key.Kind)
	}
	if len(in.CacheNodeIdsToReboot) != 1 || string(in.CacheNodeIdsToReboot[0]) != "0001" {
		return nil, failure("InvalidParameterValue", "The cache node identifier must be 0001.")
	}
	e = s.markCluster(tx, v, "reboot", "rebooting")
	v.Status = "rebooting"
	return &api.RebootCacheClusterResult{CacheCluster: clusterOutput(v, true)}, e
}
func (s *Service) clusterParameters(ctx context.Context, r Reader, action string, v Cluster) (map[string]string, error) {
	if v.ParameterGroup == "" {
		return map[string]string{}, nil
	}
	if strings.HasPrefix(v.ParameterGroup, "default.") {
		expected := "default." + family(v.Engine)
		if v.ClusterMode {
			expected += ".cluster.on"
		}
		if v.ParameterGroup != expected {
			return nil, unsupported("The default parameter group must match the engine family and cluster mode.")
		}
		return map[string]string{}, nil
	}
	k, e := resourceKey(ctx, "parametergroup", v.ParameterGroup)
	if e != nil {
		return nil, e
	}
	p, e := r.ParameterGroup(k)
	if errors.Is(e, ErrNotFound) {
		return nil, notFound(k.Kind)
	}
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, action, k, p.Tags, nil); e != nil {
		return nil, e
	}
	if p.Family != family(v.Engine) {
		return nil, unsupported("Parameter group family does not match the cache engine.")
	}
	if e = validateCapacity(p.Parameters, v.MemoryBytes); e != nil {
		return nil, e
	}
	return maps.Clone(p.Parameters), nil
}
func family(name string) string {
	if name == "valkey" {
		return "valkey8"
	}
	return "redis7"
}
func (s *Service) specification(r Reader, v Cluster) (engine.Specification, error) {
	users := []engine.User{{Name: "default", AccessString: "on ~* &* +@all", NoPassword: len(v.AuthHashes) == 0, PasswordHashes: v.AuthHashes}}
	if v.UserGroup != "" {
		g, e := r.UserGroup(Key{Scope: v.Key.Scope, Kind: "usergroup", Name: v.UserGroup})
		if e != nil {
			return engine.Specification{}, e
		}
		users = nil
		for _, id := range g.UserIDs {
			u, e := userRecord(r, Key{Scope: v.Key.Scope, Kind: "user", Name: id})
			if e != nil {
				return engine.Specification{}, e
			}
			if u.Status == "deleting" {
				continue
			}
			users = append(users, engine.User{Name: u.Name, AccessString: u.AccessString, NoPassword: u.NoPassword, PasswordHashes: u.PasswordHashes})
		}
	}
	return engine.Specification{ID: v.RuntimeID, Shards: v.Shards, Replicas: v.Replicas, ClusterMode: v.ClusterMode, TLSEnabled: v.TLSEnabled, MemoryBytes: v.MemoryBytes, Users: users, Parameters: v.Parameters}, nil
}
