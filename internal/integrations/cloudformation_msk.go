package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	api "stackd/internal/awsapi/kafka"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	owner "stackd/internal/services/kafka"
	"strings"
)

// CloudFormationMSKConfigurationOwner exposes private owner provenance, never a
// second resource store or AWS-visible management field.
type CloudFormationMSKConfigurationOwner interface {
	CloudFormationConfigurationOwnership(context.Context, string) (owner.CloudFormationOwner, error)
}

func cfnEngineLower(raw any) any {
	switch v := raw.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			key := strings.ToLower(k[:1]) + k[1:]
			if k == "EBSStorageInfo" {
				key = "ebsStorageInfo"
			}
			if k == "DataVolumeKMSKeyId" {
				key = "dataVolumeKMSKeyId"
			}
			out[key] = cfnEngineLower(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = cfnEngineLower(x)
		}
		return out
	default:
		return raw
	}
}
func cfnEngineNativeObject(raw any) (map[string]any, error) {
	body, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var p map[string]any
	if err = json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	return cfnEngineUpper(p).(map[string]any), nil
}
func cfnEngineUpper(raw any) any {
	switch v := raw.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			key := strings.ToUpper(k[:1]) + k[1:]
			switch k {
			case "ebsStorageInfo":
				key = "EBSStorageInfo"
			case "dataVolumeKMSKeyId":
				key = "DataVolumeKMSKeyId"
			}
			out[key] = cfnEngineUpper(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = cfnEngineUpper(x)
		}
		return out
	default:
		return raw
	}
}
func cfnMSKTags[M ~map[K]V, K ~string, V ~string](raw M) map[string]string {
	tags := map[string]string{}
	for k, v := range raw {
		tags[string(k)] = string(v)
	}
	return tags
}
func cfnMSKUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	desired := cfnResourceTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "kafka", "UntagResource", map[string]any{"ResourceArn": arn, "tagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "kafka", "TagResource", map[string]any{"ResourceArn": arn, "tags": desired})
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-msk-cluster.html
type cfnMSKCluster struct{ commands StepFunctionsCommands }

func (h cfnMSKCluster) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "BrokerNodeGroupInfo", "EnhancedMonitoring", "KafkaVersion", "NumberOfBrokerNodes", "EncryptionInfo", "OpenMonitoring", "ClusterName", "ClientAuthentication", "LoggingInfo", "Tags", "ConfigurationInfo", "StorageMode", "Rebalancing"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "BrokerNodeGroupInfo", "KafkaVersion", "NumberOfBrokerNodes", "ClusterName"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnMSKCluster) Replacement(a, b cloudformation.Properties) (bool, error) {
	if a["ConfigurationInfo"] != nil && b["ConfigurationInfo"] == nil {
		return true, h.Validate(b)
	}
	return cfnComputeChanged(a, b, "BrokerNodeGroupInfo", "EnhancedMonitoring", "KafkaVersion", "NumberOfBrokerNodes", "EncryptionInfo", "OpenMonitoring", "ClusterName", "ClientAuthentication", "LoggingInfo", "StorageMode", "Rebalancing"), h.Validate(b)
}
func (h cfnMSKCluster) get(ctx context.Context, arn string) (*api.ClusterInfo, error) {
	out, err := cfnComputeCall[api.DescribeClusterOutput](ctx, h.commands, "kafka", "DescribeCluster", map[string]any{"ClusterArn": arn})
	if err != nil {
		return nil, err
	}
	if out.ClusterInfo == nil {
		return nil, fmt.Errorf("MSK returned no cluster")
	}
	return out.ClusterInfo, nil
}

// cfnMSKClusterCreateContext binds the private incarnation claim persisted on
// the native cluster row. Create and RecoverCreation always use it, including
// Cloud Control creates, so public tags can never make a cluster adoptable.
func cfnMSKClusterCreateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return owner.WithCloudFormationClusterOwner(ctx, r.StackID, r.LogicalID, r.Token)
}

// cfnMSKClusterContext fences stack-owned commands inside the native owner's
// transaction. Cloud Control reads and mutations use only current native IAM.
func cfnMSKClusterContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return cfnMSKClusterCreateContext(ctx, r)
}

// find returns only a cluster visible to ctx. Cluster names are unique in a
// scope, so a fenced foreign cluster with this name proves ours is absent.
func (h cfnMSKCluster) find(ctx context.Context, name string) (*api.ClusterInfo, error) {
	input := map[string]any{"ClusterNameFilter": name}
	for {
		out, err := cfnComputeCall[api.ListClustersOutput](ctx, h.commands, "kafka", "ListClusters", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.ClusterInfoList {
			if cfnComputeValue(v.ClusterName) == name {
				found, err := h.get(ctx, cfnComputeValue(v.ClusterArn))
				if cfnEngineMissing(err) {
					return nil, nil
				}
				return found, err
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			return nil, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func cfnEngineAdmitted(id string, result cloudformation.ResourceResult, err error) (cloudformation.ResourceResult, error) {
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: id, Ref: id}, err
	}
	return result, nil
}

// cfnEngineCreateConflict reports a native same-name conflict as Cloud
// Control's AlreadyExists handler code; other failures keep their own code.
func cfnEngineCreateConflict(r cloudformation.ResourceRequest, err error) error {
	var wire *awswire.Error
	if errors.As(err, &wire) && wire.Code == "ConflictException" {
		return cfnResourceCreateOwnedError(r, err)
	}
	return err
}
func (h cfnMSKCluster) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnMSKClusterCreateContext(ctx, r)
	name := cfnComputeString(r.Properties, "ClusterName")
	v, err := h.find(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if v != nil {
		r.PhysicalID = cfnComputeValue(v.ClusterArn)
		result, err := h.Result(ctx, r)
		return cfnEngineAdmitted(r.PhysicalID, result, err)
	}
	input := cfnEngineLower(cfnComputeCopy(r.Properties, "ClusterName", "BrokerNodeGroupInfo", "EnhancedMonitoring", "KafkaVersion", "NumberOfBrokerNodes", "EncryptionInfo", "OpenMonitoring", "ClientAuthentication", "LoggingInfo", "ConfigurationInfo", "StorageMode", "Rebalancing")).(map[string]any)
	input["tags"] = cfnResourceTags(r)
	out, err := cfnComputeCall[api.CreateClusterOutput](ctx, h.commands, "kafka", "CreateCluster", input)
	if err != nil {
		// A modeled error may follow a committed admission whose reply was lost.
		if v, findErr := h.find(ctx, name); findErr == nil && v != nil {
			return cloudformation.ResourceResult{PhysicalID: cfnComputeValue(v.ClusterArn), Ref: cfnComputeValue(v.ClusterArn)}, err
		}
		return cloudformation.ResourceResult{}, cfnEngineCreateConflict(r, err)
	}
	r.PhysicalID = cfnComputeValue(out.ClusterArn)
	result, err := h.Result(ctx, r)
	return cfnEngineAdmitted(r.PhysicalID, result, err)
}
func (h cfnMSKCluster) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnMSKClusterCreateContext(ctx, r)
	v, err := h.find(ctx, cfnComputeString(r.Properties, "ClusterName"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if v == nil {
		return cloudformation.ResourceResult{}, &awswire.Error{Code: "ResourceNotFoundException", Message: "This MSK cluster incarnation has no admitted native cluster.", StatusCode: 404}
	}
	r.PhysicalID = cfnComputeValue(v.ClusterArn)
	result, err := h.Result(ctx, r)
	return cfnEngineAdmitted(r.PhysicalID, result, err)
}
func (h cfnMSKCluster) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	ctx = cfnMSKClusterContext(ctx, r)
	replacement, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replacement {
		return result, fmt.Errorf("native MSK engine, security or topology change requires replacement")
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags := cfnMSKTags(v.Tags)
	if cfnComputeChanged(r.Previous, r.Properties, "ConfigurationInfo") {
		configuration := r.Properties["ConfigurationInfo"]
		if configuration == nil {
			return result, fmt.Errorf("native MSK cannot detach its configuration; replace the cluster")
		}
		if err = cfnComputeRun(ctx, h.commands, "kafka", "UpdateClusterConfiguration", map[string]any{"ClusterArn": r.PhysicalID, "currentVersion": cfnComputeValue(v.CurrentVersion), "configurationInfo": cfnEngineLower(configuration)}); err != nil {
			return result, err
		}
	}
	if err = cfnMSKUpdateTags(ctx, h.commands, r, r.PhysicalID, tags); err != nil {
		return result, err
	}
	updated, err := h.Result(ctx, r)
	return cfnEngineAdmitted(r.PhysicalID, updated, err)
}

// Delete is fenced inside the native transaction: a cluster carrying another
// private claim is absent to this incarnation and is never deleted.
func (h cfnMSKCluster) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnMSKClusterContext(ctx, r)
	if r.PhysicalID == "" {
		v, err := h.find(ctx, cfnComputeString(r.Properties, "ClusterName"))
		if err != nil {
			return err
		}
		if v == nil {
			return nil
		}
		r.PhysicalID = cfnComputeValue(v.ClusterArn)
	}
	v, err := h.get(ctx, r.PhysicalID)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(v.State) == "DELETING" {
		return nil
	}
	if err = cfnComputeRun(ctx, h.commands, "kafka", "DeleteCluster", map[string]any{"ClusterArn": r.PhysicalID, "currentVersion": cfnComputeValue(v.CurrentVersion)}); cfnEngineMissing(err) {
		return nil
	}
	return err
}
func (h cfnMSKCluster) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(cfnMSKClusterContext(ctx, r), r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"ClusterName": cfnComputeValue(v.ClusterName), "Arn": cfnComputeValue(v.ClusterArn), "CurrentVersion": cfnComputeValue(v.CurrentVersion), "NumberOfBrokerNodes": v.NumberOfBrokerNodes, "Tags": cfnResourcePublicTags(cfnMSKTags(v.Tags))}
	for k, x := range map[string]any{"BrokerNodeGroupInfo": v.BrokerNodeGroupInfo, "ClientAuthentication": v.ClientAuthentication, "EncryptionInfo": v.EncryptionInfo} {
		if x != nil {
			p[k], err = cfnEngineNativeObject(x)
			if err != nil {
				return nil, err
			}
		}
	}
	if v.CurrentBrokerSoftwareInfo != nil {
		p["KafkaVersion"] = cfnComputeValue(v.CurrentBrokerSoftwareInfo.KafkaVersion)
		if v.CurrentBrokerSoftwareInfo.ConfigurationArn != nil {
			p["ConfigurationInfo"] = map[string]any{"Arn": cfnComputeValue(v.CurrentBrokerSoftwareInfo.ConfigurationArn), "Revision": v.CurrentBrokerSoftwareInfo.ConfigurationRevision}
		}
	}
	return p, nil
}
func (h cfnMSKCluster) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListClustersOutput](ctx, h.commands, "kafka", "ListClusters", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.ClusterInfoList {
			r.PhysicalID = cfnComputeValue(v.ClusterArn)
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
func (h cfnMSKCluster) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnMSKClusterContext(ctx, r), r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnEngineStable(cfnComputeValue(v.State), "ACTIVE")
}
func (h cfnMSKCluster) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(cfnMSKClusterContext(ctx, r), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnMSKCluster) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-msk-configuration.html
type cfnMSKConfiguration struct {
	commands StepFunctionsCommands
	owner    CloudFormationMSKConfigurationOwner
}

func (h cfnMSKConfiguration) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "ServerProperties", "KafkaVersionsList"); err != nil {
		return err
	}
	return cfnComputeRequired(p, "Name", "ServerProperties")
}
func (h cfnMSKConfiguration) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "KafkaVersionsList"), h.Validate(b)
}
func (h cfnMSKConfiguration) get(ctx context.Context, arn string) (*api.DescribeConfigurationOutput, error) {
	return cfnComputeCall[api.DescribeConfigurationOutput](ctx, h.commands, "kafka", "DescribeConfiguration", map[string]any{"Arn": arn})
}
func (h cfnMSKConfiguration) find(ctx context.Context, name string) (string, error) {
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListConfigurationsOutput](ctx, h.commands, "kafka", "ListConfigurations", input)
		if err != nil {
			return "", err
		}
		for _, v := range out.Configurations {
			if cfnComputeValue(v.Name) == name || cfnComputeValue(v.Arn) == name {
				return cfnComputeValue(v.Arn), nil
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			return "", nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMSKConfiguration) owned(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.CloudControl {
		return nil
	}
	return h.configurationOwned(ctx, r, r.PhysicalID)
}
func (h cfnMSKConfiguration) input(r cloudformation.ResourceRequest) map[string]any {
	// cfnComputeCall uses the SDK document boundary: blobs are plaintext there,
	// unlike base64 in the public Kafka REST transport.
	return map[string]any{"name": r.Properties["Name"], "description": cfnComputeDefault(r.Properties, "Description", ""), "serverProperties": cfnComputeString(r.Properties, "ServerProperties"), "kafkaVersions": r.Properties["KafkaVersionsList"]}
}

// configurationOwned checks the private claim persisted by CreateConfiguration.
func (h cfnMSKConfiguration) configurationOwned(ctx context.Context, r cloudformation.ResourceRequest, arn string) error {
	if h.owner == nil {
		return fmt.Errorf("MSK configuration ownership authority is unavailable")
	}
	claim, err := h.owner.CloudFormationConfigurationOwnership(ctx, arn)
	if err != nil {
		return err
	}
	if r.Token == "" || claim != (owner.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}) {
		return fmt.Errorf("MSK configuration %s is not owned by this stack resource incarnation", arn)
	}
	return nil
}
func (h cfnMSKConfiguration) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "Name")
	arn, err := h.find(ctx, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if arn != "" {
		if err = h.configurationOwned(ctx, r, arn); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
	} else {
		out, e := cfnComputeCall[api.CreateConfigurationOutput](owner.WithCloudFormationConfigurationOwner(ctx, r.StackID, r.LogicalID, r.Token), h.commands, "kafka", "CreateConfiguration", h.input(r))
		if e != nil {
			// A modeled error may follow a committed admission whose reply was lost.
			if arn, findErr := h.find(ctx, name); findErr == nil && arn != "" && h.configurationOwned(ctx, r, arn) == nil {
				return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn}, e
			}
			return cloudformation.ResourceResult{}, cfnEngineCreateConflict(r, e)
		}
		arn = cfnComputeValue(out.Arn)
	}
	r.PhysicalID = arn
	result, err := h.Result(ctx, r)
	return cfnEngineAdmitted(arn, result, err)
}
func (h cfnMSKConfiguration) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return result, err
	} else if replacement {
		return result, fmt.Errorf("MSK configuration name or Kafka versions require replacement")
	}
	if err := h.owned(ctx, r); err != nil {
		return result, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "ServerProperties", "Description") {
		input := h.input(r)
		delete(input, "name")
		delete(input, "kafkaVersions")
		input["Arn"] = r.PhysicalID
		if err := cfnComputeRun(ctx, h.commands, "kafka", "UpdateConfiguration", input); err != nil {
			return result, err
		}
	}
	return h.Result(ctx, r)
}
func (h cfnMSKConfiguration) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	query := r.PhysicalID
	if query == "" {
		query = cfnComputeString(r.Properties, "Name")
	}
	arn, err := h.find(ctx, query)
	if err != nil {
		return err
	}
	if arn == "" {
		return nil
	}
	r.PhysicalID = arn
	if err = h.owned(ctx, r); err != nil {
		return err
	}
	return cfnComputeRun(ctx, h.commands, "kafka", "DeleteConfiguration", map[string]any{"Arn": arn})
}
func (h cfnMSKConfiguration) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"Arn": cfnComputeValue(v.Arn), "Name": cfnComputeValue(v.Name), "Description": cfnComputeValue(v.Description), "KafkaVersionsList": cfnEngineList(v.KafkaVersions)}
	if v.LatestRevision != nil && v.LatestRevision.Revision != nil {
		revision, err := cfnComputeCall[api.DescribeConfigurationRevisionOutput](ctx, h.commands, "kafka", "DescribeConfigurationRevision", map[string]any{"Arn": r.PhysicalID, "Revision": *v.LatestRevision.Revision})
		if err != nil {
			return nil, err
		}
		p["ServerProperties"] = string(revision.ServerProperties)
		p["Description"] = cfnComputeValue(revision.Description)
		p["LatestRevision"] = map[string]any{"Revision": int64(*v.LatestRevision.Revision), "CreationTime": revision.CreationTime, "Description": cfnComputeValue(revision.Description)}
	}
	return p, nil
}
func (h cfnMSKConfiguration) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListConfigurationsOutput](ctx, h.commands, "kafka", "ListConfigurations", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Configurations {
			r.PhysicalID = cfnComputeValue(v.Arn)
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
func (h cfnMSKConfiguration) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}
