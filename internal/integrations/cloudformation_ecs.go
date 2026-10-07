package integrations

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ecs"
	"stackd/internal/services/cloudformation"
)

// ECS CloudFormation adapters delegate to the ECS owner. Task execution remains
// a real runtime effect of that owner; these adapters only drive its commands.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-cluster.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-taskdefinition.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-service.html

func cfnECSTags(tags map[string]string) []map[string]string {
	out := cfnComputeTagList(tags)
	for _, tag := range out {
		tag["key"], tag["value"] = tag["Key"], tag["Value"]
		delete(tag, "Key")
		delete(tag, "Value")
	}
	return out
}
func cfnECSTagMap(tags api.Tags) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return out
}
func cfnECSReconcileTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	added, removed := cfnCSTagChanges(current, cfnResourceTags(r))
	if len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "ecs", "UntagResource", map[string]any{"resourceArn": arn, "tagKeys": removed}); err != nil {
			return err
		}
	}
	if len(added) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "ecs", "TagResource", map[string]any{"resourceArn": arn, "tags": cfnECSTags(added)})
}
func cfnECSPublicTagList(tags map[string]string) []any { return cfnCSTagMapList(tags) }

// ---- AWS::ECS::Cluster ----

type cfnECSCluster struct{ commands StepFunctionsCommands }

const cfnECSClusterType = "AWS::ECS::Cluster"

func (h cfnECSCluster) Validate(p cloudformation.Properties) error {
	return cfnCSValidate(cfnECSClusterType, p)
}
func (h cfnECSCluster) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnECSClusterType, a, b)
}
func (h cfnECSCluster) get(ctx context.Context, name string) (*api.Cluster, error) {
	out, err := cfnComputeCall[api.DescribeClustersResponse](ctx, h.commands, "ecs", "DescribeClusters", map[string]any{"clusters": []string{name}, "include": []string{"SETTINGS", "TAGS", "CONFIGURATIONS"}})
	if err != nil {
		return nil, err
	}
	if len(out.Clusters) != 1 || cfnComputeValue(out.Clusters[0].Status) == "INACTIVE" {
		return nil, cfnCSNotFound("ECS cluster " + name)
	}
	return &out.Clusters[0], nil
}
func cfnECSClusterResult(cluster *api.Cluster) cloudformation.ResourceResult {
	name := cfnComputeValue(cluster.ClusterName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": cfnComputeValue(cluster.ClusterArn)}}
}
func (h cfnECSCluster) input(r cloudformation.ResourceRequest, name string) map[string]any {
	input := cfnCSRename(r.Properties, map[string]string{"ClusterSettings": "settings"}, "Tags", "ClusterName")
	input["clusterName"] = name
	input["tags"] = cfnECSTags(cfnResourceTags(r))
	return input
}
func (h cfnECSCluster) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "ClusterName", 255)
	if cluster, err := h.get(ctx, name); err == nil {
		if err := cfnNativeComputeOwned(ctx, r, cfnComputeValue(cluster.ClusterArn)); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return cfnECSClusterResult(cluster), nil
	} else if !cfnCSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnCSCall[api.CreateClusterResponse](ctx, h.commands, "ecs", "CreateCluster", h.input(r, name))
	if err != nil {
		if recovered, readErr := h.get(ctx, name); readErr == nil && cfnNativeComputeOwned(ctx, r, cfnComputeValue(recovered.ClusterArn)) == nil {
			return cfnECSClusterResult(recovered), err
		}
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnNativeComputeOwned(ctx, r, cfnComputeValue(out.Cluster.ClusterArn)); err != nil {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
	}
	return cfnECSClusterResult(out.Cluster), nil
}
func (h cfnECSCluster) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnECSClusterResult(cluster)
	tags := cfnECSTagMap(cluster.Tags)
	if err := cfnNativeComputeMutationOwned(ctx, r, cfnComputeValue(cluster.ClusterArn)); err != nil {
		return result, err
	}
	// The ECS owner has no PutClusterCapacityProviders control.
	if cfnComputeChanged(r.Previous, r.Properties, "CapacityProviders", "DefaultCapacityProviderStrategy") {
		return result, cfnCSUnsupported("ECS cluster capacity provider updates require PutClusterCapacityProviders, which the ECS owner does not implement")
	}
	if cfnComputeChanged(r.Previous, r.Properties, "ClusterSettings", "Configuration", "ServiceConnectDefaults") {
		input := map[string]any{"cluster": r.PhysicalID}
		if settings, ok := r.Properties["ClusterSettings"]; ok {
			input["settings"] = settings
		} else {
			// Removal restores the documented default setting.
			input["settings"] = []any{map[string]any{"Name": "containerInsights", "Value": "disabled"}}
		}
		if config, ok := r.Properties["Configuration"]; ok {
			input["configuration"] = config
		} else if r.Previous["Configuration"] != nil {
			input["configuration"] = map[string]any{}
		}
		if defaults, ok := r.Properties["ServiceConnectDefaults"]; ok {
			input["serviceConnectDefaults"] = defaults
		}
		if err := cfnCSRun(ctx, h.commands, "ecs", "UpdateCluster", input); err != nil {
			return result, err
		}
	}
	return result, cfnECSReconcileTags(ctx, h.commands, r, cfnComputeValue(cluster.ClusterArn), tags)
}
func (h cfnECSCluster) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	name := cfnComputeName(r, "ClusterName", 255)
	cluster, err := h.get(ctx, name)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, cfnComputeValue(cluster.ClusterArn)); err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "ecs", "DeleteCluster", map[string]any{"cluster": name})
	if cfnCSMissing(err, "ClusterNotFoundException") {
		return nil
	}
	return err
}
func (h cfnECSCluster) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	cluster, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(cluster, map[string]string{"settings": "ClusterSettings", "clusterArn": "Arn"})
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnECSPublicTagList(cfnECSTagMap(cluster.Tags))
	return cfnCSKeep(p, "ClusterName", "Arn", "ClusterSettings", "CapacityProviders", "DefaultCapacityProviderStrategy", "Configuration", "ServiceConnectDefaults", "Tags"), nil
}
func (h cfnECSCluster) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListClustersResponse](ctx, h.commands, "ecs", "ListClusters", input)
		if err != nil {
			return nil, err
		}
		for _, arn := range out.ClusterArns {
			name := string(arn)[strings.LastIndex(string(arn), "/")+1:]
			rows = append(rows, cloudformation.ResourceDescription{Identifier: name, Properties: cloudformation.Properties{"ClusterName": name}})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return rows, nil
		}
		input["nextToken"] = cfnComputeValue(out.NextToken)
	}
}

// ---- AWS::ECS::TaskDefinition ----

type cfnECSTaskDefinition struct{ commands StepFunctionsCommands }

const cfnECSTaskDefinitionType = "AWS::ECS::TaskDefinition"

func (h cfnECSTaskDefinition) Validate(p cloudformation.Properties) error {
	return cfnCSValidate(cfnECSTaskDefinitionType, p)
}
func (h cfnECSTaskDefinition) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnECSTaskDefinitionType, a, b)
}
func (h cfnECSTaskDefinition) describe(ctx context.Context, arn string) (*api.DescribeTaskDefinitionResponse, error) {
	out, err := cfnComputeCall[api.DescribeTaskDefinitionResponse](ctx, h.commands, "ecs", "DescribeTaskDefinition", map[string]any{"taskDefinition": arn, "include": []string{"TAGS"}})
	if cfnMessagingMissing(err, "ClientException") {
		return nil, cfnCSNotFound("ECS task definition " + arn)
	}
	if err != nil {
		return nil, err
	}
	if status := cfnComputeValue(out.TaskDefinition.Status); status != "ACTIVE" {
		return nil, cfnCSNotFound("ECS task definition " + arn)
	}
	return out, nil
}
func cfnECSTaskDefinitionResult(def *api.TaskDefinition) cloudformation.ResourceResult {
	arn := cfnComputeValue(def.TaskDefinitionArn)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"TaskDefinitionArn": arn}}
}

// owned identifies an admitted revision from the native private claim, including
// a revision deregistered after admission. Recovery must never allocate another
// revision or lose the admitted ARN merely because its later state is rejected.
func (h cfnECSTaskDefinition) owned(ctx context.Context, r cloudformation.ResourceRequest, family string) (cloudformation.ResourceResult, bool, error) {
	for _, status := range []string{"ACTIVE", "INACTIVE", "DELETE_IN_PROGRESS"} {
		input := map[string]any{"familyPrefix": family, "status": status}
		for {
			out, err := cfnComputeCall[api.ListTaskDefinitionsResponse](ctx, h.commands, "ecs", "ListTaskDefinitions", input)
			if err != nil {
				return cloudformation.ResourceResult{}, false, err
			}
			for _, arn := range out.TaskDefinitionArns {
				id := string(arn)
				if cfnNativeComputeOwned(ctx, r, id) != nil {
					continue
				}
				result := cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"TaskDefinitionArn": id}}
				def, err := cfnComputeCall[api.DescribeTaskDefinitionResponse](ctx, h.commands, "ecs", "DescribeTaskDefinition", map[string]any{"taskDefinition": id, "include": []string{"TAGS"}})
				if err != nil {
					return result, true, err
				}
				if cfnComputeValue(def.TaskDefinition.Status) != "ACTIVE" {
					return result, true, cfnCSNotFound("admitted ECS task definition " + id + " is no longer ACTIVE")
				}
				return result, true, nil
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["nextToken"] = cfnComputeValue(out.NextToken)
		}
	}
	return cloudformation.ResourceResult{}, false, nil
}
func (h cfnECSTaskDefinition) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	family := cfnComputeName(cloudformation.ResourceRequest{StackID: r.StackID, StackName: r.StackName, LogicalID: r.LogicalID, Token: r.Token, Properties: r.Properties}, "Family", 255)
	if result, admitted, err := h.owned(ctx, r, family); err != nil || admitted {
		return result, err
	}
	input := cfnCSRename(r.Properties, nil, "Tags", "Family")
	input["family"] = family
	input["tags"] = cfnECSTags(cfnResourceTags(r))
	out, err := cfnCSCall[api.RegisterTaskDefinitionResponse](ctx, h.commands, "ecs", "RegisterTaskDefinition", input)
	if err != nil {
		if result, admitted, _ := h.owned(ctx, r, family); admitted {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnNativeComputeOwned(ctx, r, cfnComputeValue(out.TaskDefinition.TaskDefinitionArn)); err != nil {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
	}
	return cfnECSTaskDefinitionResult(out.TaskDefinition), nil
}
func (h cfnECSTaskDefinition) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	def, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnECSTaskDefinitionResult(def.TaskDefinition)
	tags := cfnECSTagMap(def.Tags)
	if err := cfnNativeComputeMutationOwned(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	return result, cfnECSReconcileTags(ctx, h.commands, r, r.PhysicalID, tags)
}

// Delete deregisters the owned revision, the documented CloudFormation delete
// behavior; INACTIVE revisions remain describable as in ECS.
func (h cfnECSTaskDefinition) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	arn := r.PhysicalID
	if arn == "" {
		ctx = cfnNativeComputeContext(ctx, r, true)
		family := cfnComputeName(r, "Family", 255)
		result, admitted, err := h.owned(ctx, r, family)
		if !admitted || err != nil && !cfnCSMissing(err) {
			return err
		}
		arn = result.PhysicalID
		r.PhysicalID = arn
		ctx = cfnNativeComputeContext(ctx, r, false)
	}
	_, err := h.describe(ctx, arn)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, arn); err != nil {
		return err
	}
	return cfnComputeRun(ctx, h.commands, "ecs", "DeregisterTaskDefinition", map[string]any{"taskDefinition": arn})
}
func (h cfnECSTaskDefinition) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	def, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(def.TaskDefinition, cfnECSRenames, cfnECSPreserved...)
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnECSPublicTagList(cfnECSTagMap(def.Tags))
	return cfnCSKeep(p, "TaskDefinitionArn", "Family", "ContainerDefinitions", "Cpu", "Memory", "NetworkMode", "TaskRoleArn", "ExecutionRoleArn", "RequiresCompatibilities", "Volumes", "PlacementConstraints", "ProxyConfiguration", "InferenceAccelerators", "IpcMode", "PidMode", "RuntimePlatform", "EphemeralStorage", "EnableFaultInjection", "Tags"), nil
}

var cfnECSRenames = map[string]string{"efsVolumeConfiguration": "EFSVolumeConfiguration", "fsxWindowsFileServerVolumeConfiguration": "FSxWindowsFileServerVolumeConfiguration", "iam": "IAM", "awsvpcConfiguration": "AwsvpcConfiguration"}
var cfnECSPreserved = []string{"dockerLabels", "options", "driverOpts", "labels"}

func (h cfnECSTaskDefinition) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{"status": "ACTIVE"}
	for {
		out, err := cfnComputeCall[api.ListTaskDefinitionsResponse](ctx, h.commands, "ecs", "ListTaskDefinitions", input)
		if err != nil {
			return nil, err
		}
		for _, arn := range out.TaskDefinitionArns {
			rows = append(rows, cloudformation.ResourceDescription{Identifier: string(arn), Properties: cloudformation.Properties{"TaskDefinitionArn": string(arn)}})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return rows, nil
		}
		input["nextToken"] = cfnComputeValue(out.NextToken)
	}
}

// ---- AWS::ECS::Service ----

type cfnECSService struct{ commands StepFunctionsCommands }

const cfnECSServiceType = "AWS::ECS::Service"

func (h cfnECSService) Validate(p cloudformation.Properties) error {
	if err := cfnCSValidate(cfnECSServiceType, p); err != nil {
		return err
	}
	if raw, ok := p["ForceNewDeployment"]; ok {
		object, ok := cfnComputeObject(raw)
		if !ok {
			return fmt.Errorf("ForceNewDeployment must be an object")
		}
		if err := cfnComputeProperties(object, "EnableForceNewDeployment", "ForceNewDeploymentNonce"); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnECSService) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnECSServiceType, a, b)
}

// identity accepts the Cloud Control "ServiceArn|Cluster" identifier and the
// service ARN used as Ref.
func cfnECSServiceIdentity(id string) (service, cluster string, err error) {
	if before, after, ok := strings.Cut(id, "|"); ok {
		return before, after, nil
	}
	// arn:...:service/<cluster>/<service>
	_, resource, ok := strings.Cut(id, ":service/")
	clusterName, _, qualified := strings.Cut(resource, "/")
	if !ok || !qualified {
		return "", "", fmt.Errorf("invalid ECS service identifier %q", id)
	}
	return id, clusterName, nil
}
func (h cfnECSService) get(ctx context.Context, service, cluster string) (*api.Service, error) {
	out, err := cfnComputeCall[api.DescribeServicesResponse](ctx, h.commands, "ecs", "DescribeServices", map[string]any{"cluster": cluster, "services": []string{service}, "include": []string{"TAGS"}})
	if cfnCSMissing(err, "ClusterNotFoundException") {
		return nil, cfnCSNotFound("ECS service " + service)
	}
	if err != nil {
		return nil, err
	}
	if len(out.Services) != 1 {
		return nil, cfnCSNotFound("ECS service " + service)
	}
	return &out.Services[0], nil
}
func cfnECSServiceResult(service *api.Service) cloudformation.ResourceResult {
	arn := cfnComputeValue(service.ServiceArn)
	return cloudformation.ResourceResult{PhysicalID: arn + "|" + cfnComputeValue(service.ClusterArn), Ref: arn, Attributes: map[string]any{"Name": cfnComputeValue(service.ServiceName), "ServiceArn": arn}}
}
func (h cfnECSService) cluster(p map[string]any) string {
	if cluster := cfnComputeString(p, "Cluster"); cluster != "" {
		return cluster
	}
	return "default"
}
func (h cfnECSService) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, true)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster := h.cluster(r.Properties)
	name := cfnComputeName(cloudformation.ResourceRequest{StackID: r.StackID, StackName: r.StackName, LogicalID: r.LogicalID, Token: r.Token, Properties: r.Properties}, "ServiceName", 255)
	if service, err := h.get(ctx, name, cluster); err == nil && cfnComputeValue(service.Status) != "INACTIVE" {
		if err := cfnNativeComputeOwned(ctx, r, cfnComputeValue(service.ServiceArn)); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return cfnECSServiceResult(service), nil
	} else if err != nil && !cfnCSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnCSRename(r.Properties, map[string]string{"PlacementStrategies": "placementStrategy"}, "Tags", "ServiceName", "Cluster", "ForceNewDeployment")
	input["serviceName"] = name
	input["cluster"] = cluster
	input["tags"] = cfnECSTags(cfnResourceTags(r))
	input["clientToken"] = cfnCSClientToken(r, "CreateService", 36)
	// New replica services default DesiredCount to 1 (documented CloudFormation default).
	if _, ok := r.Properties["DesiredCount"]; !ok && cfnComputeString(r.Properties, "SchedulingStrategy") != "DAEMON" {
		input["desiredCount"] = 1
	}
	out, err := cfnCSCall[api.CreateServiceResponse](ctx, h.commands, "ecs", "CreateService", input)
	if err != nil {
		if recovered, readErr := h.get(ctx, name, cluster); readErr == nil && cfnNativeComputeOwned(ctx, r, cfnComputeValue(recovered.ServiceArn)) == nil {
			return cfnECSServiceResult(recovered), err
		}
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnNativeComputeOwned(ctx, r, cfnComputeValue(out.Service.ServiceArn)); err != nil {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
	}
	return cfnECSServiceResult(out.Service), nil
}
func (h cfnECSService) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnNativeComputeContext(ctx, r, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn, cluster, err := cfnECSServiceIdentity(r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	service, err := h.get(ctx, arn, cluster)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnECSServiceResult(service)
	tags := cfnECSTagMap(service.Tags)
	if err := cfnNativeComputeMutationOwned(ctx, r, cfnComputeValue(service.ServiceArn)); err != nil {
		return result, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "LaunchType", "DeploymentController") {
		return result, cfnCSUnsupported("the ECS owner's UpdateService does not change LaunchType or DeploymentController")
	}
	mutable := []string{"AvailabilityZoneRebalancing", "CapacityProviderStrategy", "DeploymentConfiguration", "DesiredCount", "EnableECSManagedTags", "EnableExecuteCommand", "HealthCheckGracePeriodSeconds", "LoadBalancers", "Monitoring", "NetworkConfiguration", "PlacementConstraints", "PlacementStrategies", "PlatformVersion", "PropagateTags", "ServiceConnectConfiguration", "ServiceRegistries", "TaskDefinition", "VolumeConfigurations", "VpcLatticeConfigurations"}
	force := cfnECSForce(r.Previous, r.Properties)
	if cfnComputeChanged(r.Previous, r.Properties, mutable...) || force {
		input := map[string]any{"cluster": cluster, "service": arn, "forceNewDeployment": force}
		for _, key := range mutable {
			value, ok := r.Properties[key]
			if !ok {
				if key == "LoadBalancers" && r.Previous[key] != nil {
					input["LoadBalancers"] = []any{}
				}
				continue
			}
			if key == "PlacementStrategies" {
				input["placementStrategy"] = value
				continue
			}
			input[key] = value
		}
		if err := cfnCSRun(ctx, h.commands, "ecs", "UpdateService", input); err != nil {
			return result, err
		}
	}
	return result, cfnECSReconcileTags(ctx, h.commands, r, arn, tags)
}
func cfnECSForce(before, after map[string]any) bool {
	object, _ := cfnComputeObject(after["ForceNewDeployment"])
	if enabled, _ := object["EnableForceNewDeployment"].(bool); !enabled {
		return false
	}
	previous, _ := cfnComputeObject(before["ForceNewDeployment"])
	return before == nil || !reflect.DeepEqual(previous["ForceNewDeploymentNonce"], object["ForceNewDeploymentNonce"]) || previous["EnableForceNewDeployment"] != true
}

// Stabilize waits for the primary deployment to complete, as CloudFormation
// waits for a steady service. Failed rollouts fail the stack operation.
func (h cfnECSService) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	arn, cluster, err := cfnECSServiceIdentity(r.PhysicalID)
	if err != nil {
		return false, err
	}
	service, err := h.get(ctx, arn, cluster)
	if err != nil {
		return false, err
	}
	if status := cfnComputeValue(service.Status); status != "ACTIVE" {
		return false, fmt.Errorf("ECS service %s is %s", arn, status)
	}
	for _, deployment := range service.Deployments {
		if cfnComputeValue(deployment.Status) != "PRIMARY" {
			continue
		}
		switch cfnComputeValue(deployment.RolloutState) {
		case "COMPLETED":
			return len(service.Deployments) == 1, nil
		case "FAILED":
			return false, fmt.Errorf("ECS service deployment failed: %s", cfnComputeValue(deployment.RolloutStateReason))
		}
		return false, nil
	}
	return false, nil
}

// Delete scales the owned service down and deletes it; the owner drains tasks
// asynchronously before the service becomes INACTIVE.
func (h cfnECSService) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnNativeComputeContext(ctx, r, false)
	arn, cluster := "", ""
	if r.PhysicalID != "" {
		var err error
		if arn, cluster, err = cfnECSServiceIdentity(r.PhysicalID); err != nil {
			return err
		}
	} else {
		arn, cluster = cfnComputeName(r, "ServiceName", 255), h.cluster(r.Properties)
	}
	service, err := h.get(ctx, arn, cluster)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if status := cfnComputeValue(service.Status); status != "ACTIVE" {
		return nil
	}
	if err := cfnNativeComputeMutationOwned(ctx, r, cfnComputeValue(service.ServiceArn)); err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "ecs", "DeleteService", map[string]any{"cluster": cluster, "service": arn, "force": true})
	if cfnCSMissing(err, "ServiceNotFoundException", "ClusterNotFoundException") {
		return nil
	}
	return err
}
func (h cfnECSService) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	arn, cluster := "", ""
	if r.PhysicalID != "" {
		var err error
		if arn, cluster, err = cfnECSServiceIdentity(r.PhysicalID); err != nil {
			return false, err
		}
	} else {
		arn, cluster = cfnComputeName(r, "ServiceName", 255), h.cluster(r.Properties)
	}
	service, err := h.get(ctx, arn, cluster)
	if cfnCSMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return cfnComputeValue(service.Status) == "INACTIVE", nil
}
func (h cfnECSService) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	arn, cluster, err := cfnECSServiceIdentity(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	service, err := h.get(ctx, arn, cluster)
	if err != nil {
		return nil, err
	}
	if cfnComputeValue(service.Status) == "INACTIVE" {
		return nil, cfnCSNotFound("ECS service " + arn)
	}
	p, err := cfnCSProject(service, map[string]string{"clusterArn": "Cluster", "placementStrategy": "PlacementStrategies", "awsvpcConfiguration": "AwsvpcConfiguration"})
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnECSPublicTagList(cfnECSTagMap(service.Tags))
	if p["ServiceName"] != nil {
		p["Name"] = p["ServiceName"]
	}
	return cfnCSKeep(p, "ServiceArn", "Cluster", "ServiceName", "Name", "TaskDefinition", "DesiredCount", "LaunchType", "CapacityProviderStrategy", "PlatformVersion", "NetworkConfiguration", "LoadBalancers", "DeploymentConfiguration", "DeploymentController", "SchedulingStrategy", "EnableECSManagedTags", "EnableExecuteCommand", "PropagateTags", "HealthCheckGracePeriodSeconds", "AvailabilityZoneRebalancing", "PlacementConstraints", "PlacementStrategies", "ServiceRegistries", "Tags"), nil
}
func (h cfnECSService) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	clusters, err := cfnECSCluster(h).List(ctx, r)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, cluster := range clusters {
		cdesc, err := cfnECSCluster(h).get(ctx, cluster.Identifier)
		if cfnCSMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		clusterArn := cfnComputeValue(cdesc.ClusterArn)
		input := map[string]any{"cluster": clusterArn}
		for {
			out, err := cfnComputeCall[api.ListServicesResponse](ctx, h.commands, "ecs", "ListServices", input)
			if err != nil {
				return nil, err
			}
			for _, arn := range out.ServiceArns {
				rows = append(rows, cloudformation.ResourceDescription{Identifier: string(arn) + "|" + clusterArn, Properties: cloudformation.Properties{"ServiceArn": string(arn), "Cluster": clusterArn}})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["nextToken"] = cfnComputeValue(out.NextToken)
		}
	}
	slices.SortFunc(rows, func(a, b cloudformation.ResourceDescription) int { return strings.Compare(a.Identifier, b.Identifier) })
	return rows, nil
}
