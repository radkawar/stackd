package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/elasticache"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	cacheowner "stackd/internal/services/elasticache"
	"strings"
)

// CacheCluster delegates to the native elasticache owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-cachecluster.html
type cfnCacheCacheCluster struct{ commands StepFunctionsCommands }

func (h cfnCacheCacheCluster) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "AutoMinorVersionUpgrade", "AZMode", "CacheNodeType", "CacheParameterGroupName", "CacheSecurityGroupNames", "CacheSubnetGroupName", "NotificationTopicArn", "SnapshotArns", "Port", "NumCacheNodes", "SnapshotName", "PreferredAvailabilityZones", "VpcSecurityGroupIds", "ClusterName", "Engine", "Tags", "EngineVersion", "PreferredMaintenanceWindow", "PreferredAvailabilityZone", "SnapshotWindow", "NetworkType", "IpDiscovery", "SnapshotRetentionLimit", "LogDeliveryConfigurations", "TransitEncryptionEnabled"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "CacheNodeType", "NumCacheNodes", "Engine"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCacheCacheCluster) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "AutoMinorVersionUpgrade", "AZMode", "CacheNodeType", "CacheSecurityGroupNames", "CacheSubnetGroupName", "NotificationTopicArn", "SnapshotArns", "Port", "NumCacheNodes", "SnapshotName", "PreferredAvailabilityZones", "VpcSecurityGroupIds", "ClusterName", "Engine", "EngineVersion", "PreferredMaintenanceWindow", "PreferredAvailabilityZone", "SnapshotWindow", "NetworkType", "IpDiscovery", "SnapshotRetentionLimit", "LogDeliveryConfigurations", "TransitEncryptionEnabled"), h.Validate(b)
}
func (h cfnCacheCacheCluster) get(ctx context.Context, name string) (*api.CacheCluster, error) {
	input := map[string]any{"CacheClusterId": name, "ShowCacheClustersNotInReplicationGroups": true, "ShowCacheNodeInfo": true}
	out, err := cfnComputeCall[api.DescribeCacheClustersOutput](ctx, h.commands, "elasticache", "DescribeCacheClusters", input)
	if err != nil {
		return nil, err
	}
	if len(out.CacheClusters) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.CacheClusters[0], nil
}
func (h cfnCacheCacheCluster) projection(v *api.CacheCluster) cloudformation.Properties {
	p := cloudformation.Properties{"ClusterName": cfnComputeValue(v.CacheClusterId), "Engine": cfnComputeValue(v.Engine), "EngineVersion": cfnComputeValue(v.EngineVersion), "CacheNodeType": cfnComputeValue(v.CacheNodeType), "NumCacheNodes": v.NumCacheNodes, "TransitEncryptionEnabled": v.TransitEncryptionEnabled}
	if v.CacheParameterGroup != nil {
		p["CacheParameterGroupName"] = cfnComputeValue(v.CacheParameterGroup.CacheParameterGroupName)
	}
	if len(v.CacheNodes) > 0 && v.CacheNodes[0].Endpoint != nil {
		p["RedisEndpoint"] = cfnCacheEndpoint(v.CacheNodes[0].Endpoint)
	}
	if v.ConfigurationEndpoint != nil {
		p["ConfigurationEndpoint"] = cfnCacheEndpoint(v.ConfigurationEndpoint)
	}
	return p
}
func (h cfnCacheCacheCluster) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "ClusterName", 50)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnCacheOwner(ctx, r, "cluster", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnCacheOwner(ctx, r, "cluster", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "AutoMinorVersionUpgrade", "AZMode", "CacheNodeType", "CacheParameterGroupName", "CacheSecurityGroupNames", "CacheSubnetGroupName", "NotificationTopicArn", "SnapshotArns", "Port", "NumCacheNodes", "SnapshotName", "PreferredAvailabilityZones", "VpcSecurityGroupIds", "ClusterName", "Engine", "EngineVersion", "PreferredMaintenanceWindow", "PreferredAvailabilityZone", "SnapshotWindow", "NetworkType", "IpDiscovery", "SnapshotRetentionLimit", "LogDeliveryConfigurations", "TransitEncryptionEnabled")
		delete(input, "ClusterName")
		input["CacheClusterId"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "elasticache", "CreateCacheCluster", input)
	})
	if err != nil {
		if admitted {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.read(exact, name)
	if err != nil {
		return result, err
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheCacheCluster) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "ClusterName", 50)
	p, err := h.read(cfnCacheOwner(ctx, r, "cluster", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheCacheCluster) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnCacheFence(ctx, r, "cluster", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties, "CacheParameterGroupName")
	input["CacheClusterId"] = r.PhysicalID
	input["ApplyImmediately"] = true
	if r.Properties["CacheParameterGroupName"] == nil && r.Previous["CacheParameterGroupName"] != nil {
		engine := cfnComputeValue(v.Engine)
		family := "redis7"
		if engine == "valkey" {
			family = "valkey8"
		}
		input["CacheParameterGroupName"] = "default." + family
	}
	if cfnComputeChanged(r.Previous, r.Properties, "CacheParameterGroupName") {
		if err = cfnComputeRun(ctx, h.commands, "elasticache", "ModifyCacheCluster", input); err != nil {
			return result, err
		}
	}
	if err = cfnCacheUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnCacheCacheCluster) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "ClusterName", 50)
	ctx = cfnCacheFence(ctx, r, "cluster", name)
	v, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	status := cfnComputeValue(v.CacheClusterStatus)
	if status == "deleting" {
		return nil
	}
	if status != "available" && status != "create-failed" {
		return nil
	}
	input := map[string]any{"CacheClusterId": name}
	if r.DeletionPolicy == "Snapshot" {
		input["FinalSnapshotIdentifier"] = name + "-final-" + cfnComputeHash(r.Token)[:8]
	}
	err = cfnComputeRun(ctx, h.commands, "elasticache", "DeleteCacheCluster", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnCacheCacheCluster) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnCacheFence(ctx, r, "cluster", r.PhysicalID), r.PhysicalID)
}
func (h cfnCacheCacheCluster) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnCacheCacheCluster) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{"ShowCacheClustersNotInReplicationGroups": true, "ShowCacheNodeInfo": true}
	for {
		out, err := cfnComputeCall[api.DescribeCacheClustersOutput](ctx, h.commands, "elasticache", "DescribeCacheClusters", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.CacheClusters {
			r.PhysicalID = cfnComputeValue(v.CacheClusterId)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.Marker) == "" {
			return result, nil
		}
		input["Marker"] = cfnComputeValue(out.Marker)
	}
}
func (h cfnCacheCacheCluster) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnCacheFence(ctx, r, "cluster", r.PhysicalID), r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnEngineStable(cfnComputeValue(v.CacheClusterStatus), "available")
}
func (h cfnCacheCacheCluster) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	r.PhysicalID = cfnEngineName(r, "ClusterName", 50)
	v, err := h.get(cfnCacheFence(ctx, r, "cluster", r.PhysicalID), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if cfnComputeValue(v.CacheClusterStatus) != "deleting" {
		return false, h.Delete(ctx, r)
	}
	return false, nil
}
func (h cfnCacheCacheCluster) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}

func (h cfnCacheCacheCluster) ValidateDeletionPolicy(policy string) error { return nil }

// ReplicationGroup delegates to the native elasticache owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-replicationgroup.html
type cfnCacheReplicationGroup struct{ commands StepFunctionsCommands }

func (h cfnCacheReplicationGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ReplicationGroupId", "PreferredCacheClusterAZs", "CacheSecurityGroupNames", "NodeGroupConfiguration", "LogDeliveryConfigurations", "SnapshotArns", "UserGroupIds", "Port", "NumNodeGroups", "NotificationTopicArn", "SnapshotName", "AutomaticFailoverEnabled", "ReplicasPerNodeGroup", "ReplicationGroupDescription", "MultiAZEnabled", "TransitEncryptionEnabled", "Engine", "Tags", "NumCacheClusters", "EngineVersion", "KmsKeyId", "CacheSubnetGroupName", "CacheParameterGroupName", "PreferredMaintenanceWindow", "PrimaryClusterId", "AtRestEncryptionEnabled", "AutoMinorVersionUpgrade", "SecurityGroupIds", "SnapshotWindow", "CacheNodeType", "SnapshotRetentionLimit", "SnapshottingClusterId", "AuthToken", "IpDiscovery", "NetworkType", "GlobalReplicationGroupId", "DataTieringEnabled", "TransitEncryptionMode", "ClusterMode", "Durability"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ReplicationGroupDescription", "CacheNodeType"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCacheReplicationGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ReplicationGroupId", "PreferredCacheClusterAZs", "CacheSecurityGroupNames", "NodeGroupConfiguration", "LogDeliveryConfigurations", "SnapshotArns", "Port", "NumNodeGroups", "NotificationTopicArn", "SnapshotName", "AutomaticFailoverEnabled", "ReplicasPerNodeGroup", "MultiAZEnabled", "TransitEncryptionEnabled", "Engine", "NumCacheClusters", "EngineVersion", "KmsKeyId", "CacheSubnetGroupName", "PreferredMaintenanceWindow", "PrimaryClusterId", "AtRestEncryptionEnabled", "AutoMinorVersionUpgrade", "SecurityGroupIds", "SnapshotWindow", "CacheNodeType", "SnapshotRetentionLimit", "SnapshottingClusterId", "IpDiscovery", "NetworkType", "GlobalReplicationGroupId", "DataTieringEnabled", "TransitEncryptionMode", "ClusterMode", "Durability"), h.Validate(b)
}
func (h cfnCacheReplicationGroup) get(ctx context.Context, name string) (*api.ReplicationGroup, error) {
	input := map[string]any{"ReplicationGroupId": name}
	out, err := cfnComputeCall[api.DescribeReplicationGroupsOutput](ctx, h.commands, "elasticache", "DescribeReplicationGroups", input)
	if err != nil {
		return nil, err
	}
	if len(out.ReplicationGroups) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.ReplicationGroups[0], nil
}
func (h cfnCacheReplicationGroup) projection(v *api.ReplicationGroup) cloudformation.Properties {
	p := cloudformation.Properties{"ReplicationGroupId": cfnComputeValue(v.ReplicationGroupId), "ReplicationGroupDescription": cfnComputeValue(v.Description), "Engine": cfnComputeValue(v.Engine), "CacheNodeType": cfnComputeValue(v.CacheNodeType), "ClusterMode": cfnComputeValue(v.ClusterMode), "TransitEncryptionEnabled": v.TransitEncryptionEnabled, "UserGroupIds": cfnEngineList(v.UserGroupIds), "NumNodeGroups": len(v.NodeGroups)}
	addresses, ports := []string{}, []string{}
	if len(v.NodeGroups) > 0 {
		p["ReplicasPerNodeGroup"] = len(v.NodeGroups[0].NodeGroupMembers) - 1
		p["PrimaryEndPoint"] = cfnCacheEndpoint(v.NodeGroups[0].PrimaryEndpoint)
		p["ReaderEndPoint"] = cfnCacheEndpoint(v.NodeGroups[0].PrimaryEndpoint)
	}
	for _, group := range v.NodeGroups {
		for _, member := range group.NodeGroupMembers {
			if cfnComputeValue(member.CurrentRole) != "replica" || member.ReadEndpoint == nil || member.ReadEndpoint.Port == nil {
				continue
			}
			addresses = append(addresses, cfnComputeValue(member.ReadEndpoint.Address))
			ports = append(ports, fmt.Sprint(*member.ReadEndpoint.Port))
			if len(addresses) == 1 {
				p["ReaderEndPoint"] = cfnCacheEndpoint(member.ReadEndpoint)
			}
		}
	}
	p["ReadEndPoint"] = map[string]any{"Addresses": strings.Join(addresses, ","), "AddressesList": addresses, "Ports": strings.Join(ports, ","), "PortsList": ports}
	if v.ConfigurationEndpoint != nil {
		p["ConfigurationEndPoint"] = cfnCacheEndpoint(v.ConfigurationEndpoint)
	}
	return p
}
func (h cfnCacheReplicationGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "ReplicationGroupId", 40)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnCacheOwner(ctx, r, "replicationgroup", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnCacheOwner(ctx, r, "replicationgroup", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "ReplicationGroupId", "PreferredCacheClusterAZs", "CacheSecurityGroupNames", "NodeGroupConfiguration", "LogDeliveryConfigurations", "SnapshotArns", "UserGroupIds", "Port", "NumNodeGroups", "NotificationTopicArn", "SnapshotName", "AutomaticFailoverEnabled", "ReplicasPerNodeGroup", "ReplicationGroupDescription", "MultiAZEnabled", "TransitEncryptionEnabled", "Engine", "NumCacheClusters", "EngineVersion", "KmsKeyId", "CacheSubnetGroupName", "CacheParameterGroupName", "PreferredMaintenanceWindow", "PrimaryClusterId", "AtRestEncryptionEnabled", "AutoMinorVersionUpgrade", "SecurityGroupIds", "SnapshotWindow", "CacheNodeType", "SnapshotRetentionLimit", "SnapshottingClusterId", "AuthToken", "IpDiscovery", "NetworkType", "GlobalReplicationGroupId", "DataTieringEnabled", "TransitEncryptionMode", "ClusterMode", "Durability")
		input["ReplicationGroupId"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "elasticache", "CreateReplicationGroup", input)
	})
	if err != nil {
		if admitted {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.read(exact, name)
	if err != nil {
		return result, err
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheReplicationGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "ReplicationGroupId", 40)
	p, err := h.read(cfnCacheOwner(ctx, r, "replicationgroup", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheReplicationGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnCacheFence(ctx, r, "replicationgroup", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties, "ReplicationGroupDescription", "CacheParameterGroupName", "AuthToken")
	input["ReplicationGroupId"] = r.PhysicalID
	input["ApplyImmediately"] = true
	if r.Properties["CacheParameterGroupName"] == nil && r.Previous["CacheParameterGroupName"] != nil {
		engine := cfnComputeValue(v.Engine)
		family := "redis7"
		if engine == "valkey" {
			family = "valkey8"
		}
		input["CacheParameterGroupName"] = "default." + family
	}
	if r.Properties["AuthToken"] != nil {
		input["AuthTokenUpdateStrategy"] = "SET"
	} else if r.Previous["AuthToken"] != nil {
		input["AuthTokenUpdateStrategy"] = "DELETE"
	}
	desired, e := cfnComputeStringList(r.Properties, "UserGroupIds")
	if e != nil {
		return result, e
	}
	add, remove := cfnEngineDifference(cfnEngineList(v.UserGroupIds), desired)
	input["UserGroupIdsToAdd"] = add
	input["UserGroupIdsToRemove"] = remove
	if cfnComputeChanged(r.Previous, r.Properties, "ReplicationGroupDescription", "CacheParameterGroupName", "UserGroupIds", "AuthToken") {
		if err = cfnComputeRun(ctx, h.commands, "elasticache", "ModifyReplicationGroup", input); err != nil {
			return result, err
		}
	}
	if err = cfnCacheUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnCacheReplicationGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "ReplicationGroupId", 40)
	ctx = cfnCacheFence(ctx, r, "replicationgroup", name)
	v, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	status := cfnComputeValue(v.Status)
	if status == "deleting" {
		return nil
	}
	if status != "available" && status != "create-failed" {
		return nil
	}
	input := map[string]any{"ReplicationGroupId": name}
	if r.DeletionPolicy == "Snapshot" {
		input["FinalSnapshotIdentifier"] = name + "-final-" + cfnComputeHash(r.Token)[:8]
	}
	err = cfnComputeRun(ctx, h.commands, "elasticache", "DeleteReplicationGroup", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnCacheReplicationGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnCacheFence(ctx, r, "replicationgroup", r.PhysicalID), r.PhysicalID)
}
func (h cfnCacheReplicationGroup) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	if len(v.MemberClusters) > 0 {
		out, e := cfnComputeCall[api.DescribeCacheClustersOutput](ctx, h.commands, "elasticache", "DescribeCacheClusters", map[string]any{"CacheClusterId": string(v.MemberClusters[0])})
		if e != nil {
			return nil, e
		}
		if len(out.CacheClusters) == 1 {
			member := out.CacheClusters[0]
			p["EngineVersion"] = cfnComputeValue(member.EngineVersion)
			if member.CacheParameterGroup != nil {
				p["CacheParameterGroupName"] = cfnComputeValue(member.CacheParameterGroup.CacheParameterGroupName)
			}
		}
	}
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnCacheReplicationGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeReplicationGroupsOutput](ctx, h.commands, "elasticache", "DescribeReplicationGroups", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.ReplicationGroups {
			r.PhysicalID = cfnComputeValue(v.ReplicationGroupId)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.Marker) == "" {
			return result, nil
		}
		input["Marker"] = cfnComputeValue(out.Marker)
	}
}
func (h cfnCacheReplicationGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnCacheFence(ctx, r, "replicationgroup", r.PhysicalID), r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnEngineStable(cfnComputeValue(v.Status), "available")
}
func (h cfnCacheReplicationGroup) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	r.PhysicalID = cfnEngineName(r, "ReplicationGroupId", 40)
	v, err := h.get(cfnCacheFence(ctx, r, "replicationgroup", r.PhysicalID), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if cfnComputeValue(v.Status) != "deleting" {
		return false, h.Delete(ctx, r)
	}
	return false, nil
}
func (h cfnCacheReplicationGroup) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}

func (h cfnCacheReplicationGroup) ValidateDeletionPolicy(policy string) error { return nil }

// User delegates to the native elasticache owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-user.html
type cfnCacheUser struct{ commands StepFunctionsCommands }

func (h cfnCacheUser) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "UserId", "UserName", "Engine", "AccessString", "NoPasswordRequired", "Passwords", "AuthenticationMode", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "UserId", "UserName", "Engine"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCacheUser) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "UserId", "UserName", "Engine"), h.Validate(b)
}
func (h cfnCacheUser) get(ctx context.Context, name string) (*api.User, error) {
	input := map[string]any{"UserId": name}
	out, err := cfnComputeCall[api.DescribeUsersOutput](ctx, h.commands, "elasticache", "DescribeUsers", input)
	if err != nil {
		return nil, err
	}
	if len(out.Users) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.Users[0], nil
}
func (h cfnCacheUser) projection(v *api.User) cloudformation.Properties {
	p := cloudformation.Properties{"UserId": cfnComputeValue(v.UserId), "UserName": cfnComputeValue(v.UserName), "Engine": cfnComputeValue(v.Engine), "AccessString": cfnComputeValue(v.AccessString), "Status": cfnComputeValue(v.Status), "Arn": cfnComputeValue(v.ARN)}
	if v.Authentication != nil {
		p["AuthenticationMode"] = map[string]any{"Type": cfnComputeValue(v.Authentication.Type)}
	}
	return p
}
func (h cfnCacheUser) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "UserId", 50)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnCacheOwner(ctx, r, "user", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnCacheOwner(ctx, r, "user", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "UserId", "UserName", "Engine", "AccessString", "NoPasswordRequired", "Passwords", "AuthenticationMode")
		input["UserId"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "elasticache", "CreateUser", input)
	})
	if err != nil {
		if admitted {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.read(exact, name)
	if err != nil {
		return result, err
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheUser) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "UserId", 50)
	p, err := h.read(cfnCacheOwner(ctx, r, "user", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheUser) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnCacheFence(ctx, r, "user", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties, "AccessString", "Passwords", "NoPasswordRequired", "AuthenticationMode")
	input["UserId"] = r.PhysicalID
	if !cfnComputeChanged(r.Previous, r.Properties, "Passwords", "NoPasswordRequired", "AuthenticationMode") {
		delete(input, "Passwords")
		delete(input, "NoPasswordRequired")
		delete(input, "AuthenticationMode")
	} else if r.Properties["Passwords"] == nil && r.Properties["NoPasswordRequired"] == nil && r.Properties["AuthenticationMode"] == nil {
		return result, fmt.Errorf("an explicit authentication mode is required when removing user credentials")
	}
	if r.Properties["AccessString"] == nil && r.Previous["AccessString"] != nil {
		return result, fmt.Errorf("AccessString cannot be removed")
	}
	if cfnComputeChanged(r.Previous, r.Properties, "AccessString", "Passwords", "NoPasswordRequired", "AuthenticationMode") {
		if err = cfnComputeRun(ctx, h.commands, "elasticache", "ModifyUser", input); err != nil {
			return result, err
		}
	}
	if err = cfnCacheUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnCacheUser) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "UserId", 50)
	ctx = cfnCacheFence(ctx, r, "user", name)
	v, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(v.Status) != "active" {
		return nil
	}
	input := map[string]any{"UserId": name}
	err = cfnComputeRun(ctx, h.commands, "elasticache", "DeleteUser", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnCacheUser) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnCacheFence(ctx, r, "user", r.PhysicalID), r.PhysicalID)
}
func (h cfnCacheUser) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnCacheUser) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeUsersOutput](ctx, h.commands, "elasticache", "DescribeUsers", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Users {
			r.PhysicalID = cfnComputeValue(v.UserId)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.Marker) == "" {
			return result, nil
		}
		input["Marker"] = cfnComputeValue(out.Marker)
	}
}
func (h cfnCacheUser) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnCacheFence(ctx, r, "user", r.PhysicalID), r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnEngineStable(cfnComputeValue(v.Status), "active")
}
func (h cfnCacheUser) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	r.PhysicalID = cfnEngineName(r, "UserId", 50)
	v, err := h.get(cfnCacheFence(ctx, r, "user", r.PhysicalID), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if cfnComputeValue(v.Status) != "deleting" {
		return false, h.Delete(ctx, r)
	}
	return false, nil
}
func (h cfnCacheUser) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}

// UserGroup delegates to the native elasticache owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-usergroup.html
type cfnCacheUserGroup struct{ commands StepFunctionsCommands }

func (h cfnCacheUserGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "UserGroupId", "Engine", "UserIds", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "UserGroupId", "Engine", "UserIds"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCacheUserGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "UserGroupId", "Engine"), h.Validate(b)
}
func (h cfnCacheUserGroup) get(ctx context.Context, name string) (*api.UserGroup, error) {
	input := map[string]any{"UserGroupId": name}
	out, err := cfnComputeCall[api.DescribeUserGroupsOutput](ctx, h.commands, "elasticache", "DescribeUserGroups", input)
	if err != nil {
		return nil, err
	}
	if len(out.UserGroups) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.UserGroups[0], nil
}
func (h cfnCacheUserGroup) projection(v *api.UserGroup) cloudformation.Properties {
	return cloudformation.Properties{"UserGroupId": cfnComputeValue(v.UserGroupId), "Engine": cfnComputeValue(v.Engine), "UserIds": cfnEngineList(v.UserIds), "Status": cfnComputeValue(v.Status), "Arn": cfnComputeValue(v.ARN)}
}
func (h cfnCacheUserGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "UserGroupId", 50)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnCacheOwner(ctx, r, "usergroup", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnCacheOwner(ctx, r, "usergroup", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "UserGroupId", "Engine", "UserIds")
		input["UserGroupId"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "elasticache", "CreateUserGroup", input)
	})
	if err != nil {
		if admitted {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.read(exact, name)
	if err != nil {
		return result, err
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheUserGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "UserGroupId", 50)
	p, err := h.read(cfnCacheOwner(ctx, r, "usergroup", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheUserGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnCacheFence(ctx, r, "usergroup", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties)
	input["UserGroupId"] = r.PhysicalID
	desired, e := cfnComputeStringList(r.Properties, "UserIds")
	if e != nil {
		return result, e
	}
	add, remove := cfnEngineDifference(cfnEngineList(v.UserIds), desired)
	input["UserIdsToAdd"] = add
	input["UserIdsToRemove"] = remove
	if cfnComputeChanged(r.Previous, r.Properties, "UserIds") {
		if err = cfnComputeRun(ctx, h.commands, "elasticache", "ModifyUserGroup", input); err != nil {
			return result, err
		}
	}
	if err = cfnCacheUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnCacheUserGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "UserGroupId", 50)
	ctx = cfnCacheFence(ctx, r, "usergroup", name)
	v, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(v.Status) == "deleting" {
		return nil
	}
	input := map[string]any{"UserGroupId": name}
	err = cfnComputeRun(ctx, h.commands, "elasticache", "DeleteUserGroup", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnCacheUserGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnCacheFence(ctx, r, "usergroup", r.PhysicalID), r.PhysicalID)
}
func (h cfnCacheUserGroup) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnCacheUserGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeUserGroupsOutput](ctx, h.commands, "elasticache", "DescribeUserGroups", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.UserGroups {
			r.PhysicalID = cfnComputeValue(v.UserGroupId)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.Marker) == "" {
			return result, nil
		}
		input["Marker"] = cfnComputeValue(out.Marker)
	}
}
func (h cfnCacheUserGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnCacheFence(ctx, r, "usergroup", r.PhysicalID), r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnEngineStable(cfnComputeValue(v.Status), "active")
}
func (h cfnCacheUserGroup) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	r.PhysicalID = cfnEngineName(r, "UserGroupId", 50)
	_, err := h.get(cfnCacheFence(ctx, r, "usergroup", r.PhysicalID), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, h.Delete(ctx, r)
}
func (h cfnCacheUserGroup) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}

// ParameterGroup delegates to the native elasticache owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-parametergroup.html
type cfnCacheParameterGroup struct{ commands StepFunctionsCommands }

func (h cfnCacheParameterGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Description", "Properties", "Tags", "CacheParameterGroupFamily"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Description", "CacheParameterGroupFamily"); err != nil {
		return err
	}
	if _, err := cfnEngineParameters(p["Properties"]); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCacheParameterGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Description", "CacheParameterGroupFamily"), h.Validate(b)
}
func (h cfnCacheParameterGroup) get(ctx context.Context, name string) (*api.CacheParameterGroup, error) {
	input := map[string]any{"CacheParameterGroupName": name}
	out, err := cfnComputeCall[api.DescribeCacheParameterGroupsOutput](ctx, h.commands, "elasticache", "DescribeCacheParameterGroups", input)
	if err != nil {
		return nil, err
	}
	if len(out.CacheParameterGroups) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.CacheParameterGroups[0], nil
}
func (h cfnCacheParameterGroup) projection(v *api.CacheParameterGroup) cloudformation.Properties {
	return cloudformation.Properties{"CacheParameterGroupName": cfnComputeValue(v.CacheParameterGroupName), "CacheParameterGroupFamily": cfnComputeValue(v.CacheParameterGroupFamily), "Description": cfnComputeValue(v.Description)}
}
func (h cfnCacheParameterGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "CacheParameterGroupName", 50)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnCacheOwner(ctx, r, "parametergroup", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnCacheOwner(ctx, r, "parametergroup", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "Description", "CacheParameterGroupFamily")
		input["CacheParameterGroupName"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "elasticache", "CreateCacheParameterGroup", input)
	})
	if err != nil {
		if admitted {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	if err = h.parameters(exact, r); err != nil {
		return result, err
	}
	p, err := h.read(exact, name)
	if err != nil {
		return result, err
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheParameterGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "CacheParameterGroupName", 50)
	p, err := h.read(cfnCacheOwner(ctx, r, "parametergroup", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheParameterGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnCacheFence(ctx, r, "parametergroup", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	if err = h.parameters(ctx, r); err != nil {
		return result, err
	}
	if err = cfnCacheUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnCacheParameterGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "CacheParameterGroupName", 50)
	ctx = cfnCacheFence(ctx, r, "parametergroup", name)
	_, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	input := map[string]any{"CacheParameterGroupName": name}
	err = cfnComputeRun(ctx, h.commands, "elasticache", "DeleteCacheParameterGroup", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnCacheParameterGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnCacheFence(ctx, r, "parametergroup", r.PhysicalID), r.PhysicalID)
}
func (h cfnCacheParameterGroup) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	values, e := h.parameterValues(ctx, name)
	if e != nil {
		return nil, e
	}
	p["Properties"] = values
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnCacheParameterGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeCacheParameterGroupsOutput](ctx, h.commands, "elasticache", "DescribeCacheParameterGroups", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.CacheParameterGroups {
			r.PhysicalID = cfnComputeValue(v.CacheParameterGroupName)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.Marker) == "" {
			return result, nil
		}
		input["Marker"] = cfnComputeValue(out.Marker)
	}
}
func (h cfnCacheParameterGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnCacheFence(ctx, r, "parametergroup", r.PhysicalID)
	if _, err := h.get(ctx, r.PhysicalID); err != nil {
		return false, err
	}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeCacheClustersOutput](ctx, h.commands, "elasticache", "DescribeCacheClusters", input)
		if err != nil {
			return false, err
		}
		for _, v := range out.CacheClusters {
			if v.CacheParameterGroup != nil && cfnComputeValue(v.CacheParameterGroup.CacheParameterGroupName) == r.PhysicalID {
				stable, err := cfnEngineStable(cfnComputeValue(v.CacheClusterStatus), "available")
				if !stable || err != nil {
					return stable, err
				}
			}
		}
		if cfnComputeValue(out.Marker) == "" {
			return true, nil
		}
		input["Marker"] = cfnComputeValue(out.Marker)
	}
}
func (h cfnCacheParameterGroup) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(cfnCacheFence(ctx, r, "parametergroup", r.PhysicalID), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnCacheParameterGroup) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}
func (h cfnCacheParameterGroup) parameters(ctx context.Context, r cloudformation.ResourceRequest) error {
	desired, err := cfnEngineParameters(r.Properties["Properties"])
	if err != nil {
		return err
	}
	current, err := h.parameterValues(ctx, r.PhysicalID)
	if err != nil {
		return err
	}
	if cfnEngineParametersMatch(current, desired) {
		return nil
	}
	if desired == nil {
		desired = []map[string]string{}
	}
	return cfnComputeRun(cacheowner.WithCloudFormationParameterReplacement(ctx), h.commands, "elasticache", "ModifyCacheParameterGroup", map[string]any{"CacheParameterGroupName": r.PhysicalID, "ParameterNameValues": desired})
}
func (h cfnCacheParameterGroup) parameterValues(ctx context.Context, name string) (map[string]string, error) {
	result := map[string]string{}
	input := map[string]any{"CacheParameterGroupName": name}
	input["Source"] = "user"
	for {
		out, err := cfnComputeCall[api.DescribeCacheParametersOutput](ctx, h.commands, "elasticache", "DescribeCacheParameters", input)
		if err != nil {
			return nil, err
		}
		for _, p := range out.Parameters {
			result[cfnComputeValue(p.ParameterName)] = cfnComputeValue(p.ParameterValue)
		}
		if cfnComputeValue(out.Marker) == "" {
			return result, nil
		}
		input["Marker"] = cfnComputeValue(out.Marker)
	}
}

// SubnetGroup delegates to the native elasticache owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-subnetgroup.html
type cfnCacheSubnetGroup struct{ commands StepFunctionsCommands }

func (h cfnCacheSubnetGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Description", "SubnetIds", "CacheSubnetGroupName", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Description", "SubnetIds"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCacheSubnetGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "CacheSubnetGroupName"), h.Validate(b)
}
func (h cfnCacheSubnetGroup) get(ctx context.Context, name string) (*api.CacheSubnetGroup, error) {
	input := map[string]any{"CacheSubnetGroupName": name}
	out, err := cfnComputeCall[api.DescribeCacheSubnetGroupsOutput](ctx, h.commands, "elasticache", "DescribeCacheSubnetGroups", input)
	if err != nil {
		return nil, err
	}
	if len(out.CacheSubnetGroups) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.CacheSubnetGroups[0], nil
}
func (h cfnCacheSubnetGroup) projection(v *api.CacheSubnetGroup) cloudformation.Properties {
	p := cloudformation.Properties{"CacheSubnetGroupName": cfnComputeValue(v.CacheSubnetGroupName), "Description": cfnComputeValue(v.CacheSubnetGroupDescription)}
	ids := make([]string, 0, len(v.Subnets))
	for _, s := range v.Subnets {
		ids = append(ids, cfnComputeValue(s.SubnetIdentifier))
	}
	p["SubnetIds"] = ids
	return p
}
func (h cfnCacheSubnetGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "CacheSubnetGroupName", 50)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnCacheOwner(ctx, r, "subnetgroup", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnCacheOwner(ctx, r, "subnetgroup", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "Description", "SubnetIds")
		input["CacheSubnetGroupDescription"] = input["Description"]
		delete(input, "Description")
		input["CacheSubnetGroupName"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "elasticache", "CreateCacheSubnetGroup", input)
	})
	if err != nil {
		if admitted {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.read(exact, name)
	if err != nil {
		return result, err
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheSubnetGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "CacheSubnetGroupName", 50)
	p, err := h.read(cfnCacheOwner(ctx, r, "subnetgroup", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnEngineResult(name, p)
}
func (h cfnCacheSubnetGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnCacheFence(ctx, r, "subnetgroup", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties, "Description", "SubnetIds")
	input["CacheSubnetGroupName"] = r.PhysicalID
	if x, ok := input["Description"]; ok {
		input["CacheSubnetGroupDescription"] = x
		delete(input, "Description")
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Description", "SubnetIds") {
		if err = cfnComputeRun(ctx, h.commands, "elasticache", "ModifyCacheSubnetGroup", input); err != nil {
			return result, err
		}
	}
	if err = cfnCacheUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnCacheSubnetGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "CacheSubnetGroupName", 50)
	ctx = cfnCacheFence(ctx, r, "subnetgroup", name)
	_, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	input := map[string]any{"CacheSubnetGroupName": name}
	err = cfnComputeRun(ctx, h.commands, "elasticache", "DeleteCacheSubnetGroup", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnCacheSubnetGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnCacheFence(ctx, r, "subnetgroup", r.PhysicalID), r.PhysicalID)
}
func (h cfnCacheSubnetGroup) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	tags, err := cfnCacheTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnCacheSubnetGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeCacheSubnetGroupsOutput](ctx, h.commands, "elasticache", "DescribeCacheSubnetGroups", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.CacheSubnetGroups {
			r.PhysicalID = cfnComputeValue(v.CacheSubnetGroupName)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.Marker) == "" {
			return result, nil
		}
		input["Marker"] = cfnComputeValue(out.Marker)
	}
}
func (h cfnCacheSubnetGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(cfnCacheFence(ctx, r, "subnetgroup", r.PhysicalID), r.PhysicalID)
	return err == nil, err
}
func (h cfnCacheSubnetGroup) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(cfnCacheFence(ctx, r, "subnetgroup", r.PhysicalID), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnCacheSubnetGroup) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}
