package elasticache

import (
	"context"
	"fmt"
	"slices"
	engine "stackd/engine/valkey"
	api "stackd/internal/awsapi/elasticache"
	"strings"
)

func endpoint(v engine.Endpoint) *api.Endpoint {
	if v.Address == "" || v.Port == 0 {
		return nil
	}
	return &api.Endpoint{Address: new(api.String(v.Address)), Port: new(api.Integer(v.Port))}
}
func memberName(v Cluster, n engine.Node) string {
	return fmt.Sprintf("%s-%04d", v.Key.Name, n.Shard*(v.Replicas+1)+n.Replica+1)
}
func clusterOutput(v Cluster, showNodes bool) *api.CacheCluster {
	parameter := v.ParameterGroup
	if parameter == "" {
		parameter = "default." + family(v.Engine)
		if v.ClusterMode {
			parameter += ".cluster.on"
		}
	}
	status := "in-sync"
	if v.Status != "available" {
		status = "applying"
	}
	out := &api.CacheCluster{ARN: new(api.String(v.Key.ARN())), CacheClusterId: new(api.String(v.Key.Name)), CacheClusterStatus: new(api.String(v.Status)), CacheClusterCreateTime: new(v.Created), Engine: new(api.String(v.Engine)), EngineVersion: new(api.String(v.EngineVersion)), CacheNodeType: new(api.String(v.NodeType)), NumCacheNodes: new(api.IntegerOptional(1)), TransitEncryptionEnabled: new(api.BooleanOptional(v.TLSEnabled)), AtRestEncryptionEnabled: new(api.BooleanOptional(false)), AuthTokenEnabled: new(api.BooleanOptional(len(v.AuthHashes) > 0)), AutoMinorVersionUpgrade: new(api.Boolean(false)), SnapshotRetentionLimit: new(api.IntegerOptional(0)), CacheParameterGroup: &api.CacheParameterGroupStatus{CacheParameterGroupName: new(api.String(parameter)), ParameterApplyStatus: new(api.String(status))}}
	if showNodes {
		for _, n := range v.Nodes {
			out.CacheNodes = append(out.CacheNodes, api.CacheNode{CacheNodeId: new(api.String("0001")), CacheNodeStatus: new(api.String(v.Status)), CacheNodeCreateTime: new(v.Created), Endpoint: endpoint(n.Endpoint), ParameterGroupStatus: new(api.String(status))})
		}
	}
	return out
}
func replicationOutput(v Cluster) *api.ReplicationGroup {
	mode := "disabled"
	if v.ClusterMode {
		mode = "enabled"
	}
	out := &api.ReplicationGroup{ARN: new(api.String(v.Key.ARN())), ReplicationGroupId: new(api.String(v.Key.Name)), Description: new(api.String(v.Description)), Status: new(api.String(v.Status)), Engine: new(api.String(v.Engine)), CacheNodeType: new(api.String(v.NodeType)), ReplicationGroupCreateTime: new(v.Created), ClusterEnabled: new(api.BooleanOptional(v.ClusterMode)), ClusterMode: new(api.ClusterMode(mode)), AutomaticFailover: new(api.AutomaticFailoverStatusDISABLED), MultiAZ: new(api.MultiAZStatusDISABLED), TransitEncryptionEnabled: new(api.BooleanOptional(v.TLSEnabled)), AtRestEncryptionEnabled: new(api.BooleanOptional(false)), AuthTokenEnabled: new(api.BooleanOptional(len(v.AuthHashes) > 0)), SnapshotRetentionLimit: new(api.IntegerOptional(0)), AutoMinorVersionUpgrade: new(api.Boolean(false))}
	if v.TLSEnabled {
		out.TransitEncryptionMode = new(api.TransitEncryptionMode("required"))
	}
	if v.UserGroup != "" {
		out.UserGroupIds = api.UserGroupIdList{api.UserGroupId(v.UserGroup)}
	}
	for shard := int32(0); shard < v.Shards; shard++ {
		g := api.NodeGroup{NodeGroupId: new(api.String(fmt.Sprintf("%04d", shard+1))), Status: new(api.String(v.Status))}
		if v.ClusterMode {
			g.Slots = new(api.String(fmt.Sprintf("%d-%d", 16384*shard/v.Shards, 16384*(shard+1)/v.Shards-1)))
		}
		for _, n := range v.Nodes {
			if n.Shard != shard {
				continue
			}
			name := memberName(v, n)
			out.MemberClusters = append(out.MemberClusters, api.String(name))
			role := "replica"
			if n.Replica == 0 {
				role = "primary"
				g.PrimaryEndpoint = endpoint(n.Endpoint)
				if v.ClusterMode && shard == 0 {
					out.ConfigurationEndpoint = endpoint(n.Endpoint)
				}
			}
			g.NodeGroupMembers = append(g.NodeGroupMembers, api.NodeGroupMember{CacheClusterId: new(api.String(name)), CacheNodeId: new(api.String("0001")), CurrentRole: new(api.String(role)), ReadEndpoint: endpoint(n.Endpoint)})
		}
		out.NodeGroups = append(out.NodeGroups, g)
	}
	return out
}
func (s *Service) describeClusters(ctx context.Context, tx Transaction, in *api.DescribeCacheClustersMessage) (*api.CacheClusterMessage, error) {
	if e := s.authorize(ctx, "DescribeCacheClusters", Key{}, nil, nil); e != nil && in.CacheClusterId == nil {
		return nil, e
	}
	all, e := tx.Clusters(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	out := []api.CacheCluster{}
	for _, v := range all {
		if v.Key.Kind == "cluster" {
			if in.CacheClusterId != nil && strings.ToLower(value(in.CacheClusterId)) != v.Key.Name {
				continue
			}
			if e = s.authorize(ctx, "DescribeCacheClusters", v.Key, v.Tags, nil); e != nil {
				return nil, e
			}
			out = append(out, *clusterOutput(v, boolean(in.ShowCacheNodeInfo)))
			continue
		}
		if boolean(in.ShowCacheClustersNotInReplicationGroups) {
			continue
		}
		for _, n := range v.Nodes {
			name := memberName(v, n)
			if in.CacheClusterId != nil && strings.ToLower(value(in.CacheClusterId)) != name {
				continue
			}
			member := v
			member.Key = Key{Scope: v.Key.Scope, Kind: "cluster", Name: name}
			member.Nodes = []engine.Node{n}
			if e = s.authorize(ctx, "DescribeCacheClusters", member.Key, v.Tags, nil); e != nil {
				return nil, e
			}
			item := clusterOutput(member, boolean(in.ShowCacheNodeInfo))
			item.ReplicationGroupId = new(api.String(v.Key.Name))
			out = append(out, *item)
		}
	}
	if in.CacheClusterId != nil && len(out) == 0 {
		return nil, notFound("cluster")
	}
	slices.SortFunc(out, func(a, b api.CacheCluster) int {
		return strings.Compare(value(a.CacheClusterId), value(b.CacheClusterId))
	})
	selected, next, e := page(ctx, "DescribeCacheClusters", value(in.CacheClusterId)+fmt.Sprint(boolean(in.ShowCacheClustersNotInReplicationGroups), boolean(in.ShowCacheNodeInfo)), out, in.Marker, in.MaxRecords, func(v api.CacheCluster) string { return value(v.CacheClusterId) })
	return &api.CacheClusterMessage{CacheClusters: selected, Marker: next}, e
}
func (s *Service) describeReplicationGroups(ctx context.Context, tx Transaction, in *api.DescribeReplicationGroupsMessage) (*api.ReplicationGroupMessage, error) {
	var all []Cluster
	var e error
	if in.ReplicationGroupId != nil {
		v, err := s.loadCluster(ctx, tx, "DescribeReplicationGroups", "replicationgroup", value(in.ReplicationGroupId))
		e = err
		all = []Cluster{v}
	} else {
		e = s.authorize(ctx, "DescribeReplicationGroups", Key{}, nil, nil)
		if e == nil {
			all, e = tx.Clusters(scopeFor(ctx))
		}
	}
	if e != nil {
		return nil, e
	}
	filtered := all[:0]
	for _, v := range all {
		if v.Key.Kind == "replicationgroup" {
			filtered = append(filtered, v)
		}
	}
	selected, next, e := page(ctx, "DescribeReplicationGroups", value(in.ReplicationGroupId), filtered, in.Marker, in.MaxRecords, func(v Cluster) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.ReplicationGroupMessage{Marker: next}
	for _, v := range selected {
		out.ReplicationGroups = append(out.ReplicationGroups, *replicationOutput(v))
	}
	return out, nil
}
func (s *Service) describeEngineVersions(ctx context.Context, _ Transaction, in *api.DescribeCacheEngineVersionsMessage) (*api.CacheEngineVersionMessage, error) {
	if e := s.authorize(ctx, "DescribeCacheEngineVersions", Key{}, nil, nil); e != nil {
		return nil, e
	}
	items := []api.CacheEngineVersion{}
	for _, name := range []string{"redis", "valkey"} {
		_, version, _ := engineVersion(name, "")
		if in.Engine != nil && value(in.Engine) != name || in.EngineVersion != nil && value(in.EngineVersion) != version || in.CacheParameterGroupFamily != nil && value(in.CacheParameterGroupFamily) != family(name) {
			continue
		}
		description := "Valkey " + engine.Version
		if name == "redis" {
			description += " with Redis " + engine.RedisCompatibility + " protocol compatibility"
		}
		items = append(items, api.CacheEngineVersion{Engine: new(api.String(name)), EngineVersion: new(api.String(version)), CacheParameterGroupFamily: new(api.String(family(name))), CacheEngineDescription: new(api.String(description)), CacheEngineVersionDescription: new(api.String(description))})
	}
	selected, next, e := page(ctx, "DescribeCacheEngineVersions", value(in.Engine)+"/"+value(in.EngineVersion)+"/"+value(in.CacheParameterGroupFamily), items, in.Marker, in.MaxRecords, func(v api.CacheEngineVersion) string { return value(v.Engine) })
	return &api.CacheEngineVersionMessage{CacheEngineVersions: selected, Marker: next}, e
}
