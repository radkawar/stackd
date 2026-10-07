package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/memorydb"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	memoryowner "stackd/internal/services/memorydb"
)

// Cluster delegates to the native memorydb owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-memorydb-cluster.html
type cfnMemoryCluster struct{ commands StepFunctionsCommands }

func (h cfnMemoryCluster) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ClusterName", "Description", "MultiRegionClusterName", "NodeType", "NumShards", "NumReplicasPerShard", "SubnetGroupName", "SecurityGroupIds", "MaintenanceWindow", "ParameterGroupName", "Port", "SnapshotRetentionLimit", "SnapshotWindow", "ACLName", "SnsTopicArn", "SnsTopicStatus", "TLSEnabled", "DataTiering", "NetworkType", "IpDiscovery", "KmsKeyId", "SnapshotArns", "SnapshotName", "FinalSnapshotName", "Engine", "EngineVersion", "AutoMinorVersionUpgrade", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ClusterName", "NodeType", "ACLName"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnMemoryCluster) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ClusterName", "MultiRegionClusterName", "NodeType", "NumShards", "NumReplicasPerShard", "SubnetGroupName", "SecurityGroupIds", "MaintenanceWindow", "Port", "SnapshotRetentionLimit", "SnapshotWindow", "SnsTopicArn", "SnsTopicStatus", "TLSEnabled", "DataTiering", "NetworkType", "IpDiscovery", "KmsKeyId", "SnapshotArns", "SnapshotName", "Engine", "EngineVersion", "AutoMinorVersionUpgrade"), h.Validate(b)
}
func (h cfnMemoryCluster) get(ctx context.Context, name string) (*api.Cluster, error) {
	input := map[string]any{"ClusterName": name}
	out, err := cfnComputeCall[api.DescribeClustersOutput](ctx, h.commands, "memorydb", "DescribeClusters", input)
	if err != nil {
		return nil, err
	}
	if len(out.Clusters) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.Clusters[0], nil
}
func (h cfnMemoryCluster) projection(v *api.Cluster) cloudformation.Properties {
	p := cloudformation.Properties{"ClusterName": cfnComputeValue(v.Name), "Description": cfnComputeValue(v.Description), "NodeType": cfnComputeValue(v.NodeType), "ACLName": cfnComputeValue(v.ACLName), "Engine": cfnComputeValue(v.Engine), "EngineVersion": cfnComputeValue(v.EngineVersion), "TLSEnabled": v.TLSEnabled, "NumShards": v.NumberOfShards, "ParameterGroupName": cfnComputeValue(v.ParameterGroupName), "Status": cfnComputeValue(v.Status), "ClusterEndpoint": v.ClusterEndpoint, "ParameterGroupStatus": cfnComputeValue(v.ParameterGroupStatus), "DataTiering": cfnComputeValue(v.DataTiering), "AutoMinorVersionUpgrade": v.AutoMinorVersionUpgrade, "SnapshotRetentionLimit": v.SnapshotRetentionLimit, "ARN": cfnComputeValue(v.ARN)}
	if len(v.Shards) > 0 && v.Shards[0].NumberOfNodes != nil {
		p["NumReplicasPerShard"] = int32(*v.Shards[0].NumberOfNodes) - 1
	}
	return p
}
func (h cfnMemoryCluster) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "ClusterName", 40)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnMemoryOwner(ctx, r, "cluster", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnMemoryOwner(ctx, r, "cluster", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "ClusterName", "Description", "MultiRegionClusterName", "NodeType", "NumShards", "NumReplicasPerShard", "SubnetGroupName", "SecurityGroupIds", "MaintenanceWindow", "ParameterGroupName", "Port", "SnapshotRetentionLimit", "SnapshotWindow", "ACLName", "SnsTopicArn", "SnsTopicStatus", "TLSEnabled", "DataTiering", "NetworkType", "IpDiscovery", "KmsKeyId", "SnapshotArns", "SnapshotName", "Engine", "EngineVersion", "AutoMinorVersionUpgrade")
		input["ClusterName"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "memorydb", "CreateCluster", input)
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
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemoryCluster) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "ClusterName", 40)
	p, err := h.read(cfnMemoryOwner(ctx, r, "cluster", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemoryCluster) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnMemoryFence(ctx, r, "cluster", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties, "Description", "ACLName", "ParameterGroupName")
	input["ClusterName"] = r.PhysicalID
	if r.Properties["Description"] == nil {
		input["Description"] = ""
	}
	if r.Properties["ParameterGroupName"] == nil && r.Previous["ParameterGroupName"] != nil {
		engine := cfnComputeValue(v.Engine)
		family := "memorydb_redis7"
		if engine == "valkey" {
			family = "memorydb_valkey7"
		}
		input["ParameterGroupName"] = "default." + family
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Description", "ACLName", "ParameterGroupName") {
		if err = cfnComputeRun(ctx, h.commands, "memorydb", "UpdateCluster", input); err != nil {
			return result, err
		}
	}
	if err = cfnMemoryUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnMemoryCluster) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "ClusterName", 40)
	ctx = cfnMemoryFence(ctx, r, "cluster", name)
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
	if status == "creating" || status == "modifying" || status == "starting" {
		return nil
	}
	input := map[string]any{"ClusterName": name}
	if x := r.Properties["FinalSnapshotName"]; x != nil {
		input["FinalSnapshotName"] = x
	}
	err = cfnComputeRun(ctx, h.commands, "memorydb", "DeleteCluster", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnMemoryCluster) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnMemoryFence(ctx, r, "cluster", r.PhysicalID), r.PhysicalID)
}
func (h cfnMemoryCluster) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnMemoryCluster) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeClustersOutput](ctx, h.commands, "memorydb", "DescribeClusters", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Clusters {
			r.PhysicalID = cfnComputeValue(v.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMemoryCluster) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnMemoryFence(ctx, r, "cluster", r.PhysicalID), r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnEngineStable(cfnComputeValue(v.Status), "available")
}
func (h cfnMemoryCluster) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	r.PhysicalID = cfnEngineName(r, "ClusterName", 40)
	v, err := h.get(cfnMemoryFence(ctx, r, "cluster", r.PhysicalID), r.PhysicalID)
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
func (h cfnMemoryCluster) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnMemoryARNResult(r.PhysicalID, p)
}

// User delegates to the native memorydb owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-memorydb-user.html
type cfnMemoryUser struct{ commands StepFunctionsCommands }

func (h cfnMemoryUser) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "UserName", "AccessString", "AuthenticationMode", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "UserName"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnMemoryUser) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "UserName"), h.Validate(b)
}
func (h cfnMemoryUser) get(ctx context.Context, name string) (*api.User, error) {
	input := map[string]any{"UserName": name}
	out, err := cfnComputeCall[api.DescribeUsersOutput](ctx, h.commands, "memorydb", "DescribeUsers", input)
	if err != nil {
		return nil, err
	}
	if len(out.Users) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.Users[0], nil
}
func (h cfnMemoryUser) projection(v *api.User) cloudformation.Properties {
	p := cloudformation.Properties{"UserName": cfnComputeValue(v.Name), "AccessString": cfnComputeValue(v.AccessString), "Status": cfnComputeValue(v.Status), "Arn": cfnComputeValue(v.ARN)}
	if v.Authentication != nil {
		p["AuthenticationMode"] = map[string]any{"Type": cfnComputeValue(v.Authentication.Type)}
	}
	return p
}
func (h cfnMemoryUser) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "UserName", 50)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnMemoryOwner(ctx, r, "user", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnMemoryOwner(ctx, r, "user", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "UserName", "AccessString", "AuthenticationMode")
		input["UserName"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "memorydb", "CreateUser", input)
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
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemoryUser) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "UserName", 50)
	p, err := h.read(cfnMemoryOwner(ctx, r, "user", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemoryUser) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnMemoryFence(ctx, r, "user", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties, "AccessString", "AuthenticationMode")
	input["UserName"] = r.PhysicalID
	if !cfnComputeChanged(r.Previous, r.Properties, "AuthenticationMode") {
		delete(input, "AuthenticationMode")
	} else if r.Properties["AuthenticationMode"] == nil {
		return result, fmt.Errorf("removing password authentication requires replacing the MemoryDB user")
	}
	if r.Properties["AccessString"] == nil && r.Previous["AccessString"] != nil {
		return result, fmt.Errorf("MemoryDB user access must be explicit")
	}
	if cfnComputeChanged(r.Previous, r.Properties, "AccessString", "AuthenticationMode") {
		if err = cfnComputeRun(ctx, h.commands, "memorydb", "UpdateUser", input); err != nil {
			return result, err
		}
	}
	if err = cfnMemoryUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnMemoryUser) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "UserName", 50)
	ctx = cfnMemoryFence(ctx, r, "user", name)
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
	input := map[string]any{"UserName": name}
	err = cfnComputeRun(ctx, h.commands, "memorydb", "DeleteUser", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnMemoryUser) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnMemoryFence(ctx, r, "user", r.PhysicalID), r.PhysicalID)
}
func (h cfnMemoryUser) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnMemoryUser) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeUsersOutput](ctx, h.commands, "memorydb", "DescribeUsers", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Users {
			r.PhysicalID = cfnComputeValue(v.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMemoryUser) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnMemoryFence(ctx, r, "user", r.PhysicalID), r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnEngineStable(cfnComputeValue(v.Status), "active")
}
func (h cfnMemoryUser) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	r.PhysicalID = cfnEngineName(r, "UserName", 50)
	v, err := h.get(cfnMemoryFence(ctx, r, "user", r.PhysicalID), r.PhysicalID)
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
func (h cfnMemoryUser) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnMemoryARNResult(r.PhysicalID, p)
}

// ACL delegates to the native memorydb owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-memorydb-acl.html
type cfnMemoryACL struct{ commands StepFunctionsCommands }

func (h cfnMemoryACL) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ACLName", "UserNames", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ACLName"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnMemoryACL) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ACLName"), h.Validate(b)
}
func (h cfnMemoryACL) get(ctx context.Context, name string) (*api.ACL, error) {
	input := map[string]any{"ACLName": name}
	out, err := cfnComputeCall[api.DescribeACLsOutput](ctx, h.commands, "memorydb", "DescribeACLs", input)
	if err != nil {
		return nil, err
	}
	if len(out.ACLs) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.ACLs[0], nil
}
func (h cfnMemoryACL) projection(v *api.ACL) cloudformation.Properties {
	return cloudformation.Properties{"ACLName": cfnComputeValue(v.Name), "UserNames": cfnEngineList(v.UserNames), "Status": cfnComputeValue(v.Status), "Arn": cfnComputeValue(v.ARN)}
}
func (h cfnMemoryACL) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "ACLName", 50)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnMemoryOwner(ctx, r, "acl", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnMemoryOwner(ctx, r, "acl", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "ACLName", "UserNames")
		input["ACLName"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "memorydb", "CreateACL", input)
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
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemoryACL) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "ACLName", 50)
	p, err := h.read(cfnMemoryOwner(ctx, r, "acl", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemoryACL) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnMemoryFence(ctx, r, "acl", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties)
	input["ACLName"] = r.PhysicalID
	desired, e := cfnComputeStringList(r.Properties, "UserNames")
	if e != nil {
		return result, e
	}
	add, remove := cfnEngineDifference(cfnEngineList(v.UserNames), desired)
	input["UserNamesToAdd"] = add
	input["UserNamesToRemove"] = remove
	if cfnComputeChanged(r.Previous, r.Properties, "UserNames") {
		if err = cfnComputeRun(ctx, h.commands, "memorydb", "UpdateACL", input); err != nil {
			return result, err
		}
	}
	if err = cfnMemoryUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnMemoryACL) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "ACLName", 50)
	ctx = cfnMemoryFence(ctx, r, "acl", name)
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
	input := map[string]any{"ACLName": name}
	err = cfnComputeRun(ctx, h.commands, "memorydb", "DeleteACL", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnMemoryACL) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnMemoryFence(ctx, r, "acl", r.PhysicalID), r.PhysicalID)
}
func (h cfnMemoryACL) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnMemoryACL) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeACLsOutput](ctx, h.commands, "memorydb", "DescribeACLs", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.ACLs {
			r.PhysicalID = cfnComputeValue(v.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMemoryACL) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnMemoryFence(ctx, r, "acl", r.PhysicalID), r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnEngineStable(cfnComputeValue(v.Status), "active")
}
func (h cfnMemoryACL) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	r.PhysicalID = cfnEngineName(r, "ACLName", 50)
	_, err := h.get(cfnMemoryFence(ctx, r, "acl", r.PhysicalID), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, h.Delete(ctx, r)
}
func (h cfnMemoryACL) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnMemoryARNResult(r.PhysicalID, p)
}

// ParameterGroup delegates to the native memorydb owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-memorydb-parametergroup.html
type cfnMemoryParameterGroup struct{ commands StepFunctionsCommands }

func (h cfnMemoryParameterGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ParameterGroupName", "Family", "Description", "Tags", "Parameters"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ParameterGroupName", "Family"); err != nil {
		return err
	}
	if _, err := cfnEngineParameters(p["Parameters"]); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnMemoryParameterGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ParameterGroupName", "Family", "Description"), h.Validate(b)
}
func (h cfnMemoryParameterGroup) get(ctx context.Context, name string) (*api.ParameterGroup, error) {
	input := map[string]any{"ParameterGroupName": name}
	out, err := cfnComputeCall[api.DescribeParameterGroupsOutput](ctx, h.commands, "memorydb", "DescribeParameterGroups", input)
	if err != nil {
		return nil, err
	}
	if len(out.ParameterGroups) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.ParameterGroups[0], nil
}
func (h cfnMemoryParameterGroup) projection(v *api.ParameterGroup) cloudformation.Properties {
	return cloudformation.Properties{"ParameterGroupName": cfnComputeValue(v.Name), "Family": cfnComputeValue(v.Family), "Description": cfnComputeValue(v.Description), "ARN": cfnComputeValue(v.ARN)}
}
func (h cfnMemoryParameterGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "ParameterGroupName", 50)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnMemoryOwner(ctx, r, "parametergroup", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnMemoryOwner(ctx, r, "parametergroup", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "ParameterGroupName", "Family", "Description")
		input["ParameterGroupName"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "memorydb", "CreateParameterGroup", input)
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
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemoryParameterGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "ParameterGroupName", 50)
	p, err := h.read(cfnMemoryOwner(ctx, r, "parametergroup", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemoryParameterGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnMemoryFence(ctx, r, "parametergroup", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	if err = h.parameters(ctx, r); err != nil {
		return result, err
	}
	if err = cfnMemoryUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnMemoryParameterGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "ParameterGroupName", 50)
	ctx = cfnMemoryFence(ctx, r, "parametergroup", name)
	_, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	input := map[string]any{"ParameterGroupName": name}
	err = cfnComputeRun(ctx, h.commands, "memorydb", "DeleteParameterGroup", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnMemoryParameterGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnMemoryFence(ctx, r, "parametergroup", r.PhysicalID), r.PhysicalID)
}
func (h cfnMemoryParameterGroup) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	values, e := h.parameterValues(ctx, name)
	if e != nil {
		return nil, e
	}
	p["Parameters"] = values
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnMemoryParameterGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeParameterGroupsOutput](ctx, h.commands, "memorydb", "DescribeParameterGroups", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.ParameterGroups {
			r.PhysicalID = cfnComputeValue(v.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMemoryParameterGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnMemoryFence(ctx, r, "parametergroup", r.PhysicalID)
	if _, err := h.get(ctx, r.PhysicalID); err != nil {
		return false, err
	}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeClustersOutput](ctx, h.commands, "memorydb", "DescribeClusters", input)
		if err != nil {
			return false, err
		}
		for _, v := range out.Clusters {
			if cfnComputeValue(v.ParameterGroupName) == r.PhysicalID {
				stable, err := cfnEngineStable(cfnComputeValue(v.Status), "available")
				if !stable || err != nil {
					return stable, err
				}
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			return true, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMemoryParameterGroup) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(cfnMemoryFence(ctx, r, "parametergroup", r.PhysicalID), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnMemoryParameterGroup) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnMemoryARNResult(r.PhysicalID, p)
}
func (h cfnMemoryParameterGroup) parameters(ctx context.Context, r cloudformation.ResourceRequest) error {
	desired, err := cfnEngineParameters(r.Properties["Parameters"])
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
	return cfnComputeRun(memoryowner.WithCloudFormationParameterReplacement(ctx), h.commands, "memorydb", "UpdateParameterGroup", map[string]any{"ParameterGroupName": r.PhysicalID, "ParameterNameValues": desired})
}
func (h cfnMemoryParameterGroup) parameterValues(ctx context.Context, name string) (map[string]string, error) {
	result := map[string]string{}
	input := map[string]any{"ParameterGroupName": name}
	for {
		out, err := cfnComputeCall[api.DescribeParametersOutput](memoryowner.WithCloudFormationParameterReplacement(ctx), h.commands, "memorydb", "DescribeParameters", input)
		if err != nil {
			return nil, err
		}
		for _, p := range out.Parameters {
			result[cfnComputeValue(p.Name)] = cfnComputeValue(p.Value)
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}

// SubnetGroup delegates to the native memorydb owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-memorydb-subnetgroup.html
type cfnMemorySubnetGroup struct{ commands StepFunctionsCommands }

func (h cfnMemorySubnetGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "SubnetGroupName", "Description", "SubnetIds", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "SubnetGroupName", "SubnetIds"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnMemorySubnetGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "SubnetGroupName"), h.Validate(b)
}
func (h cfnMemorySubnetGroup) get(ctx context.Context, name string) (*api.SubnetGroup, error) {
	input := map[string]any{"SubnetGroupName": name}
	out, err := cfnComputeCall[api.DescribeSubnetGroupsOutput](ctx, h.commands, "memorydb", "DescribeSubnetGroups", input)
	if err != nil {
		return nil, err
	}
	if len(out.SubnetGroups) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.SubnetGroups[0], nil
}
func (h cfnMemorySubnetGroup) projection(v *api.SubnetGroup) cloudformation.Properties {
	p := cloudformation.Properties{"SubnetGroupName": cfnComputeValue(v.Name), "Description": cfnComputeValue(v.Description), "ARN": cfnComputeValue(v.ARN), "SupportedNetworkTypes": cfnEngineList(v.SupportedNetworkTypes)}
	ids := make([]string, 0, len(v.Subnets))
	for _, s := range v.Subnets {
		ids = append(ids, cfnComputeValue(s.Identifier))
	}
	p["SubnetIds"] = ids
	return p
}
func (h cfnMemorySubnetGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "SubnetGroupName", 50)
	r.PhysicalID = name
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	exact := cfnMemoryOwner(ctx, r, "subnetgroup", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnMemoryOwner(ctx, r, "subnetgroup", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "SubnetGroupName", "Description", "SubnetIds")
		input["SubnetGroupName"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "memorydb", "CreateSubnetGroup", input)
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
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemorySubnetGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "SubnetGroupName", 50)
	p, err := h.read(cfnMemoryOwner(ctx, r, "subnetgroup", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnMemoryARNResult(name, p)
}
func (h cfnMemorySubnetGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnMemoryFence(ctx, r, "subnetgroup", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties, "Description", "SubnetIds")
	input["SubnetGroupName"] = r.PhysicalID
	if cfnComputeChanged(r.Previous, r.Properties, "Description", "SubnetIds") {
		if err = cfnComputeRun(ctx, h.commands, "memorydb", "UpdateSubnetGroup", input); err != nil {
			return result, err
		}
	}
	if err = cfnMemoryUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnMemorySubnetGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "SubnetGroupName", 50)
	ctx = cfnMemoryFence(ctx, r, "subnetgroup", name)
	_, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	input := map[string]any{"SubnetGroupName": name}
	err = cfnComputeRun(ctx, h.commands, "memorydb", "DeleteSubnetGroup", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnMemorySubnetGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnMemoryFence(ctx, r, "subnetgroup", r.PhysicalID), r.PhysicalID)
}
func (h cfnMemorySubnetGroup) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnMemorySubnetGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeSubnetGroupsOutput](ctx, h.commands, "memorydb", "DescribeSubnetGroups", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.SubnetGroups {
			r.PhysicalID = cfnComputeValue(v.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMemorySubnetGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(cfnMemoryFence(ctx, r, "subnetgroup", r.PhysicalID), r.PhysicalID)
	return err == nil, err
}
func (h cfnMemorySubnetGroup) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(cfnMemoryFence(ctx, r, "subnetgroup", r.PhysicalID), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnMemorySubnetGroup) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnMemoryARNResult(r.PhysicalID, p)
}

// Snapshot delegates to the native memorydb owner, including its bounded topology admission.
// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-memorydb-snapshot.html
type cfnMemorySnapshot struct{ commands StepFunctionsCommands }

func (h cfnMemorySnapshot) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "SnapshotName", "ClusterName", "KmsKeyId", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "SnapshotName", "ClusterName"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnMemorySnapshot) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "SnapshotName", "ClusterName", "KmsKeyId"), h.Validate(b)
}
func (h cfnMemorySnapshot) get(ctx context.Context, name string) (*api.Snapshot, error) {
	input := map[string]any{"SnapshotName": name}
	out, err := cfnComputeCall[api.DescribeSnapshotsOutput](ctx, h.commands, "memorydb", "DescribeSnapshots", input)
	if err != nil {
		return nil, err
	}
	if len(out.Snapshots) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native resource not found", StatusCode: 404}
	}
	return &out.Snapshots[0], nil
}
func (h cfnMemorySnapshot) projection(v *api.Snapshot) cloudformation.Properties {
	p := cloudformation.Properties{"SnapshotName": cfnComputeValue(v.Name), "Status": cfnComputeValue(v.Status), "Source": cfnComputeValue(v.Source), "ClusterConfiguration": v.ClusterConfiguration, "DataTiering": cfnComputeValue(v.DataTiering), "Arn": cfnComputeValue(v.ARN)}
	if v.ClusterConfiguration != nil {
		p["ClusterName"] = cfnComputeValue(v.ClusterConfiguration.Name)
	}
	return p
}
func (h cfnMemorySnapshot) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnEngineName(r, "SnapshotName", 50)
	r.PhysicalID = name
	result := cfnMemorySnapshotResult(r, name)
	exact := cfnMemoryOwner(ctx, r, "snapshot", name, false)
	admitted, err := cfnEngineAdmit(r, exact, cfnMemoryOwner(ctx, r, "snapshot", name, true), func(c context.Context) error { _, e := h.get(c, name); return e }, func(c context.Context) error {
		input := cfnComputeCopy(r.Properties, "SnapshotName", "ClusterName", "KmsKeyId")
		input["SnapshotName"] = name
		input["Tags"] = cfnComputeTagList(cfnEngineUserTags(r))
		return cfnComputeRun(c, h.commands, "memorydb", "CreateSnapshot", input)
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
	return cfnEngineResult(cfnComputeString(p, "Arn"), p)
}
func (h cfnMemorySnapshot) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnEngineName(r, "SnapshotName", 50)
	p, err := h.read(cfnMemoryOwner(ctx, r, "snapshot", name, false), name)
	if err != nil {
		return cloudformation.ResourceResult{}, cfnEngineAbsent(err)
	}
	return cfnEngineResult(cfnComputeString(p, "Arn"), p)
}

// cfnMemorySnapshotResult is the admitted snapshot identity: its scoped ARN.
func cfnMemorySnapshotResult(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	arn := "arn:" + r.Scope.Partition + ":memorydb:" + r.Scope.Region + ":" + r.Scope.Account + ":snapshot/" + name
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn}
}
func (h cfnMemorySnapshot) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("native engine or topology update requires replacement")
	}
	ctx = cfnMemoryFence(ctx, r, "snapshot", r.PhysicalID)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	if err = cfnMemoryUpdateTags(ctx, h.commands, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnMemorySnapshot) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnEngineName(r, "SnapshotName", 50)
	ctx = cfnMemoryFence(ctx, r, "snapshot", name)
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
	if status != "available" && status != "failed" {
		return nil
	}
	input := map[string]any{"SnapshotName": name}
	err = cfnComputeRun(ctx, h.commands, "memorydb", "DeleteSnapshot", input)
	if cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnMemorySnapshot) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(cfnMemoryFence(ctx, r, "snapshot", r.PhysicalID), r.PhysicalID)
}
func (h cfnMemorySnapshot) read(ctx context.Context, name string) (cloudformation.Properties, error) {
	v, err := h.get(ctx, name)
	if err != nil {
		return nil, err
	}
	p := h.projection(v)
	tags, err := cfnMemoryTags(ctx, h.commands, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnMemorySnapshot) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeSnapshotsOutput](ctx, h.commands, "memorydb", "DescribeSnapshots", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Snapshots {
			r.PhysicalID = cfnComputeValue(v.ARN)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMemorySnapshot) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnMemoryFence(ctx, r, "snapshot", r.PhysicalID), r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnEngineStable(cfnComputeValue(v.Status), "available")
}
func (h cfnMemorySnapshot) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	r.PhysicalID = cfnEngineName(r, "SnapshotName", 50)
	v, err := h.get(cfnMemoryFence(ctx, r, "snapshot", r.PhysicalID), r.PhysicalID)
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
func (h cfnMemorySnapshot) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(cfnComputeString(p, "Arn"), p)
}
