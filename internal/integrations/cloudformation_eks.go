package integrations

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	api "stackd/internal/awsapi/eks"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
)

// EKS CloudFormation adapters drive the EKS owner's asynchronous lifecycles.
// Kubernetes control planes, workers and add-ons require the configured native
// runtime; the owner rejects requests when that runtime is absent.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-cluster.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-nodegroup.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-addon.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-fargateprofile.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-accessentry.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-podidentityassociation.html

func cfnEKSTagMap(tags api.TagMap) map[string]string {
	out := make(map[string]string, len(tags))
	for key, value := range tags {
		out[string(key)] = string(value)
	}
	return out
}
func cfnEKSReconcileTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current, owned map[string]string) error {
	desired := owned
	added, removed := cfnCSTagChanges(current, desired)
	if len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "eks", "UntagResource", map[string]any{"resourceArn": arn, "tagKeys": removed}); err != nil {
			return err
		}
	}
	if len(added) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "eks", "TagResource", map[string]any{"resourceArn": arn, "tags": added})
}

// cfnEKSPending reports whether an owner update is in progress and returns the
// failure of the most recent completed update when it did not succeed.
func cfnEKSPending(ctx context.Context, c StepFunctionsCommands, scope map[string]any) (bool, error) {
	input := maps.Clone(scope)
	var latest *api.Update
	for {
		out, err := cfnComputeCall[api.ListUpdatesResponse](ctx, c, "eks", "ListUpdates", input)
		if err != nil {
			return false, err
		}
		for _, id := range out.UpdateIds {
			describe := maps.Clone(scope)
			describe["updateId"] = string(id)
			update, err := cfnComputeCall[api.DescribeUpdateResponse](ctx, c, "eks", "DescribeUpdate", describe)
			if err != nil {
				return false, err
			}
			if cfnComputeValue(update.Update.Status) == "InProgress" {
				return true, nil
			}
			if latest == nil || update.Update.CreatedAt != nil && latest.CreatedAt != nil && time.Time(*update.Update.CreatedAt).After(time.Time(*latest.CreatedAt)) {
				latest = update.Update
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			break
		}
		input["nextToken"] = cfnComputeValue(out.NextToken)
	}
	if latest != nil && cfnComputeValue(latest.Status) != "Successful" {
		messages := make([]string, 0, len(latest.Errors))
		for _, detail := range latest.Errors {
			messages = append(messages, cfnComputeValue(detail.ErrorMessage))
		}
		return false, fmt.Errorf("EKS update %s %s: %s", cfnComputeValue(latest.Id), cfnComputeValue(latest.Status), strings.Join(messages, "; "))
	}
	return false, nil
}

// ---- AWS::EKS::Cluster ----

type cfnEKSCluster struct{ commands StepFunctionsCommands }

const cfnEKSClusterType = "AWS::EKS::Cluster"

var cfnEKSLogTypes = []string{"api", "audit", "authenticator", "controllerManager", "scheduler"}

func (h cfnEKSCluster) Validate(p cloudformation.Properties) error {
	if err := cfnEKSValidate(cfnEKSClusterType, p); err != nil {
		return err
	}
	_, err := cfnEKSLogging(p)
	return err
}
func (h cfnEKSCluster) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnEKSClusterType, a, b)
}

// cfnEKSLogging converts CloudFormation EnabledTypes to the set of enabled types.
func cfnEKSLogging(p map[string]any) ([]string, error) {
	logging, _ := cfnComputeObject(p["Logging"])
	cluster, _ := cfnComputeObject(logging["ClusterLogging"])
	raw, _ := cluster["EnabledTypes"].([]any)
	var out []string
	for _, item := range raw {
		object, ok := cfnComputeObject(item)
		kind, _ := object["Type"].(string)
		if !ok || !slices.Contains(cfnEKSLogTypes, kind) {
			return nil, fmt.Errorf("invalid EKS logging type %v", item)
		}
		out = append(out, kind)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
func cfnEKSLoggingInput(enabled []string, complete bool) map[string]any {
	setups := []any{}
	if len(enabled) > 0 {
		setups = append(setups, map[string]any{"types": enabled, "enabled": true})
	}
	if complete {
		var disabled []string
		for _, kind := range cfnEKSLogTypes {
			if !slices.Contains(enabled, kind) {
				disabled = append(disabled, kind)
			}
		}
		if len(disabled) > 0 {
			setups = append(setups, map[string]any{"types": disabled, "enabled": false})
		}
	}
	return map[string]any{"clusterLogging": setups}
}
func cfnEKSEnabledLogs(cluster *api.Cluster) []string {
	var out []string
	if cluster.Logging != nil {
		for _, setup := range cluster.Logging.ClusterLogging {
			if setup.Enabled != nil && bool(*setup.Enabled) {
				for _, kind := range setup.Types {
					out = append(out, string(kind))
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
func (h cfnEKSCluster) get(ctx context.Context, name string) (*api.Cluster, error) {
	out, err := cfnComputeCall[api.DescribeClusterResponse](ctx, h.commands, "eks", "DescribeCluster", map[string]any{"name": name})
	if err != nil {
		return nil, err
	}
	return out.Cluster, nil
}
func cfnEKSClusterResult(cluster *api.Cluster) cloudformation.ResourceResult {
	name := cfnComputeValue(cluster.Name)
	attributes := map[string]any{"Arn": cfnComputeValue(cluster.Arn), "Id": cfnComputeValue(cluster.Id), "Endpoint": cfnComputeValue(cluster.Endpoint)}
	if cluster.CertificateAuthority != nil {
		attributes["CertificateAuthorityData"] = cfnComputeValue(cluster.CertificateAuthority.Data)
	}
	if cluster.ResourcesVpcConfig != nil {
		attributes["ClusterSecurityGroupId"] = cfnComputeValue(cluster.ResourcesVpcConfig.ClusterSecurityGroupId)
	}
	if cluster.Identity != nil && cluster.Identity.Oidc != nil {
		attributes["OpenIdConnectIssuerUrl"] = cfnComputeValue(cluster.Identity.Oidc.Issuer)
	}
	if len(cluster.EncryptionConfig) > 0 && cluster.EncryptionConfig[0].Provider != nil {
		attributes["EncryptionConfigKeyArn"] = cfnComputeValue(cluster.EncryptionConfig[0].Provider.KeyArn)
	}
	if cluster.KubernetesNetworkConfig != nil && cluster.KubernetesNetworkConfig.ServiceIpv6Cidr != nil {
		attributes["KubernetesNetworkConfig.ServiceIpv6Cidr"] = cfnComputeValue(cluster.KubernetesNetworkConfig.ServiceIpv6Cidr)
	}
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: attributes}
}
func (h cfnEKSCluster) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, recoveryErr := cfnEKSRecoveryID(ctx, h.commands, r)
	if recoveryErr == nil {
		r.PhysicalID = id
	} else if !cfnCSMissing(recoveryErr) {
		return cloudformation.ResourceResult{}, recoveryErr
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 100)
	if cluster, err := h.get(ctx, name); err == nil {
		if err := cfnEKSOwned(ctx, h.commands, r, cfnEKSExpectedID(r)); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return cfnEKSClusterResult(cluster), nil
	} else if !cfnCSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnCSRename(r.Properties, nil, "Tags", "Name", "Logging", "Force")
	input["name"] = name
	input["tags"] = cfnEKSResourceTags(r)
	input["clientRequestToken"] = cfnCSClientToken(r, "CreateCluster", 64)
	if r.Properties["Logging"] != nil {
		enabled, _ := cfnEKSLogging(r.Properties)
		input["logging"] = cfnEKSLoggingInput(enabled, false)
	}
	out, err := cfnCSCall[api.CreateClusterResponse](cfnEKSCreateContext(ctx, r), h.commands, "eks", "CreateCluster", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSClusterResult(out.Cluster), nil
}

// converge issues at most one owner update: EKS admits a single configuration
// update at a time and only while the cluster is ACTIVE.
func (h cfnEKSCluster) converge(ctx context.Context, r cloudformation.ResourceRequest, cluster *api.Cluster) (bool, error) {
	name := cfnComputeValue(cluster.Name)
	if version := cfnComputeString(r.Properties, "Version"); version != "" && version != cfnComputeValue(cluster.Version) {
		force, _ := r.Properties["Force"].(bool)
		return true, cfnComputeRun(ctx, h.commands, "eks", "UpdateClusterVersion", map[string]any{"name": name, "version": version, "force": force, "clientRequestToken": cfnCSClientToken(r, "version/"+version, 64)})
	}
	enabled, err := cfnEKSLogging(r.Properties)
	if err != nil {
		return false, err
	}
	if !slices.Equal(enabled, cfnEKSEnabledLogs(cluster)) {
		return true, cfnComputeRun(ctx, h.commands, "eks", "UpdateClusterConfig", map[string]any{"name": name, "logging": cfnEKSLoggingInput(enabled, true), "clientRequestToken": cfnCSClientToken(r, "logging/"+strings.Join(enabled, ","), 64)})
	}
	access, _ := cfnComputeObject(r.Properties["AccessConfig"])
	if mode, _ := access["AuthenticationMode"].(string); mode != "" && (cluster.AccessConfig == nil || mode != cfnComputeValue(cluster.AccessConfig.AuthenticationMode)) {
		return true, cfnComputeRun(ctx, h.commands, "eks", "UpdateClusterConfig", map[string]any{"name": name, "accessConfig": map[string]any{"authenticationMode": mode}, "clientRequestToken": cfnCSClientToken(r, "access/"+mode, 64)})
	}
	protect, _ := r.Properties["DeletionProtection"].(bool)
	if current := cluster.DeletionProtection != nil && bool(*cluster.DeletionProtection); current != protect {
		return true, cfnComputeRun(ctx, h.commands, "eks", "UpdateClusterConfig", map[string]any{"name": name, "deletionProtection": protect, "clientRequestToken": cfnCSClientToken(r, fmt.Sprintf("protection/%t", protect), 64)})
	}
	return false, nil
}
func (h cfnEKSCluster) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnEKSContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEKSClusterResult(cluster)
	tags := cfnEKSTagMap(cluster.Tags)
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	// Remaining mutable controls are submitted to the owner, which admits or
	// rejects them; version, logging, access and protection converge below.
	other := []string{"ResourcesVpcConfig", "KubernetesNetworkConfig", "UpgradePolicy", "ZonalShiftConfig", "ComputeConfig", "StorageConfig", "RemoteNetworkConfig", "ControlPlaneScalingConfig", "KubeApiServerConfig", "KubeSchedulerConfig", "KubeControllerManagerConfig"}
	if cfnComputeChanged(r.Previous, r.Properties, other...) {
		input := map[string]any{"name": r.PhysicalID}
		for _, key := range other {
			if cfnComputeChanged(r.Previous, r.Properties, key) && r.Properties[key] != nil {
				input[key] = r.Properties[key]
			}
		}
		if err := cfnCSRun(ctx, h.commands, "eks", "UpdateClusterConfig", input); err != nil {
			return result, err
		}
	}
	if err := cfnEKSReconcileTags(ctx, h.commands, r, cfnComputeValue(cluster.Arn), tags, cfnEKSResourceTags(r)); err != nil {
		return result, err
	}
	if cfnComputeValue(cluster.Status) == "ACTIVE" {
		if pending, err := cfnEKSPending(ctx, h.commands, map[string]any{"name": r.PhysicalID}); err != nil || pending {
			return result, nil
		}
		_, err = h.converge(ctx, r, cluster)
	}
	return result, err
}

// Stabilize waits for ACTIVE and drives remaining serial cluster updates.
func (h cfnEKSCluster) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnEKSContext(ctx, r)
	cluster, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	switch status := cfnComputeValue(cluster.Status); status {
	case "ACTIVE":
	case "FAILED", "DELETING":
		return false, fmt.Errorf("EKS cluster %s is %s", r.PhysicalID, status)
	default:
		return false, nil
	}
	pending, err := cfnEKSPending(ctx, h.commands, map[string]any{"name": r.PhysicalID})
	if err != nil || pending {
		return false, err
	}
	issued, err := h.converge(ctx, r, cluster)
	return !issued && err == nil, err
}

// Result refreshes endpoint and certificate data published at ACTIVE.
func (h cfnEKSCluster) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnEKSContext(ctx, r)
	cluster, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSClusterResult(cluster), nil
}
func (h cfnEKSCluster) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		id, err := cfnEKSRecoveryID(ctx, h.commands, r)
		if cfnCSMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		r.PhysicalID = id
	}
	ctx = cfnEKSContext(ctx, r)
	name := cfnComputeName(r, "Name", 100)
	cluster, err := h.get(ctx, name)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(cluster.Status) == "DELETING" {
		return nil
	}
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eks", "DeleteCluster", map[string]any{"name": name}))
}
func (h cfnEKSCluster) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnEKSContext(ctx, r)
	cluster, err := h.get(ctx, cfnComputeName(r, "Name", 100))
	if cfnCSMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if status := cfnComputeValue(cluster.Status); status != "DELETING" {
		return false, fmt.Errorf("EKS cluster deletion stopped in %s", status)
	}
	return false, nil
}
func (h cfnEKSCluster) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	cluster, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(cluster, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range cfnEKSClusterResult(cluster).Attributes {
		if !strings.Contains(key, ".") {
			p[key] = value
		}
	}
	if vpc, ok := p["ResourcesVpcConfig"].(map[string]any); ok {
		p["ResourcesVpcConfig"] = map[string]any(cfnCSKeep(vpc, "SubnetIds", "SecurityGroupIds", "EndpointPublicAccess", "EndpointPrivateAccess", "PublicAccessCidrs"))
	}
	if access, ok := p["AccessConfig"].(map[string]any); ok {
		p["AccessConfig"] = map[string]any(cfnCSKeep(access, "AuthenticationMode", "BootstrapClusterCreatorAdminPermissions"))
	}
	types := []any{}
	for _, kind := range cfnEKSEnabledLogs(cluster) {
		types = append(types, map[string]any{"Type": kind})
	}
	p["Logging"] = map[string]any{"ClusterLogging": map[string]any{"EnabledTypes": types}}
	p["Tags"] = cfnEKSPublicTags(cfnEKSTagMap(cluster.Tags))
	return cfnCSKeep(p, "Name", "Arn", "Id", "Endpoint", "CertificateAuthorityData", "ClusterSecurityGroupId", "OpenIdConnectIssuerUrl", "EncryptionConfigKeyArn", "RoleArn", "Version", "ResourcesVpcConfig", "AccessConfig", "Logging", "DeletionProtection", "KubernetesNetworkConfig", "EncryptionConfig", "Tags"), nil
}
func (h cfnEKSCluster) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	names, err := cfnCSEKSClusters(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	rows := make([]cloudformation.ResourceDescription, 0, len(names))
	for _, name := range names {
		rows = append(rows, cloudformation.ResourceDescription{Identifier: name, Properties: cloudformation.Properties{"Name": name}})
	}
	return rows, nil
}

// ---- AWS::EKS::Nodegroup ----

type cfnEKSNodegroup struct{ commands StepFunctionsCommands }

const cfnEKSNodegroupType = "AWS::EKS::Nodegroup"

// Nodegroup Tags and Labels are CloudFormation JSON maps, not tag lists.
func cfnEKSMapTags(p map[string]any) (map[string]string, error) {
	out := map[string]string{}
	if p["Tags"] == nil {
		return out, nil
	}
	object, ok := cfnComputeObject(p["Tags"])
	if !ok {
		return nil, fmt.Errorf("property Tags must be an object")
	}
	for key, raw := range object {
		value, ok := raw.(string)
		if !ok || key == "" {
			return nil, fmt.Errorf("property Tags requires string values")
		}
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, fmt.Errorf("reserved tag key %s", key)
		}
		out[key] = value
	}
	return out, nil
}
func cfnEKSMapResourceTags(r cloudformation.ResourceRequest) map[string]string {
	user, _ := cfnEKSMapTags(r.Properties)
	if len(r.Tags) == 0 {
		if len(user) == 0 {
			return nil
		}
		return user
	}
	tags := maps.Clone(r.Tags)
	maps.Copy(tags, user)
	return tags
}
func (h cfnEKSNodegroup) Validate(p cloudformation.Properties) error {
	if err := cloudformation.ValidateResourceProperties(cfnEKSNodegroupType, p); err != nil {
		return err
	}
	_, err := cfnEKSMapTags(p)
	return err
}
func (h cfnEKSNodegroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnEKSNodegroupType, a, b)
}
func cfnEKSNodegroupIdentity(id string) (string, string, error) {
	cluster, nodegroup, ok := strings.Cut(id, "/")
	if !ok || cluster == "" || nodegroup == "" {
		return "", "", fmt.Errorf("invalid EKS nodegroup identifier %q", id)
	}
	return cluster, nodegroup, nil
}
func (h cfnEKSNodegroup) name(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		_, name, _ := cfnEKSNodegroupIdentity(r.PhysicalID)
		return name
	}
	return cfnComputeName(r, "NodegroupName", 63)
}
func (h cfnEKSNodegroup) get(ctx context.Context, cluster, name string) (*api.Nodegroup, error) {
	out, err := cfnComputeCall[api.DescribeNodegroupResponse](ctx, h.commands, "eks", "DescribeNodegroup", map[string]any{"clusterName": cluster, "nodegroupName": name})
	if err != nil {
		return nil, err
	}
	return out.Nodegroup, nil
}
func cfnEKSNodegroupResult(n *api.Nodegroup) cloudformation.ResourceResult {
	id := cfnComputeValue(n.ClusterName) + "/" + cfnComputeValue(n.NodegroupName)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": cfnComputeValue(n.NodegroupArn), "ClusterName": cfnComputeValue(n.ClusterName), "NodegroupName": cfnComputeValue(n.NodegroupName), "Id": id}}
}
func (h cfnEKSNodegroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, recoveryErr := cfnEKSRecoveryID(ctx, h.commands, r)
	if recoveryErr == nil {
		r.PhysicalID = id
	} else if !cfnCSMissing(recoveryErr) {
		return cloudformation.ResourceResult{}, recoveryErr
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, name := cfnComputeString(r.Properties, "ClusterName"), h.name(r)
	if n, err := h.get(ctx, cluster, name); err == nil {
		if err := cfnEKSOwned(ctx, h.commands, r, cfnEKSExpectedID(r)); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return cfnEKSNodegroupResult(n), nil
	} else if !cfnCSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnCSRename(r.Properties, nil, "Tags", "NodegroupName", "ForceUpdateEnabled")
	input["nodegroupName"] = name
	input["tags"] = cfnEKSMapResourceTags(r)
	input["clientRequestToken"] = cfnCSClientToken(r, "CreateNodegroup", 64)
	out, err := cfnCSCall[api.CreateNodegroupResponse](cfnEKSCreateContext(ctx, r), h.commands, "eks", "CreateNodegroup", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSNodegroupResult(out.Nodegroup), nil
}
func cfnEKSLabels(p map[string]any) map[string]string {
	object, _ := cfnComputeObject(p["Labels"])
	out := map[string]string{}
	for key, value := range object {
		out[key], _ = value.(string)
	}
	return out
}
func cfnEKSTaintKey(v any) string {
	object, _ := cfnComputeObject(v)
	return fmt.Sprint(object["Key"]) + "\x00" + fmt.Sprint(object["Effect"])
}

// converge issues one nodegroup update at a time, as the EKS owner requires.
func (h cfnEKSNodegroup) converge(ctx context.Context, r cloudformation.ResourceRequest, n *api.Nodegroup) (bool, error) {
	cluster, name := cfnComputeValue(n.ClusterName), cfnComputeValue(n.NodegroupName)
	force, _ := r.Properties["ForceUpdateEnabled"].(bool)
	version := cfnComputeString(r.Properties, "Version")
	release := cfnComputeString(r.Properties, "ReleaseVersion")
	template, _ := cfnComputeObject(r.Properties["LaunchTemplate"])
	templateVersion, _ := template["Version"].(string)
	currentTemplateVersion := ""
	if n.LaunchTemplate != nil {
		currentTemplateVersion = cfnComputeValue(n.LaunchTemplate.Version)
	}
	if version != "" && version != cfnComputeValue(n.Version) || release != "" && release != cfnComputeValue(n.ReleaseVersion) || templateVersion != "" && templateVersion != currentTemplateVersion {
		input := map[string]any{"clusterName": cluster, "nodegroupName": name, "force": force}
		if template != nil {
			input["launchTemplate"] = template
		} else {
			if version != "" {
				input["version"] = version
			}
			if release != "" {
				input["releaseVersion"] = release
			}
		}
		input["clientRequestToken"] = cfnCSClientToken(r, fmt.Sprintf("version/%s/%s/%s", version, release, templateVersion), 64)
		return true, cfnCSRun(ctx, h.commands, "eks", "UpdateNodegroupVersion", input)
	}
	input := map[string]any{"clusterName": cluster, "nodegroupName": name}
	desiredLabels, currentLabels := cfnEKSLabels(r.Properties), map[string]string{}
	for key, value := range n.Labels {
		currentLabels[string(key)] = string(value)
	}
	if !maps.Equal(desiredLabels, currentLabels) {
		added, removed := cfnCSTagChanges(currentLabels, desiredLabels)
		labels := map[string]any{}
		if len(added) > 0 {
			labels["addOrUpdateLabels"] = added
		}
		if len(removed) > 0 {
			labels["removeLabels"] = removed
		}
		input["labels"] = labels
	}
	desiredTaints, _ := r.Properties["Taints"].([]any)
	current, err := cfnCSProject(map[string]any{"taints": n.Taints}, nil)
	if err != nil {
		return false, err
	}
	currentTaints, _ := current["Taints"].([]any)
	if !cfnCSSameSet(desiredTaints, currentTaints) {
		keys := map[string]bool{}
		for _, taint := range desiredTaints {
			keys[cfnEKSTaintKey(taint)] = true
		}
		var removed []any
		for _, taint := range currentTaints {
			if !keys[cfnEKSTaintKey(taint)] {
				removed = append(removed, taint)
			}
		}
		taints := map[string]any{}
		if len(desiredTaints) > 0 {
			taints["addOrUpdateTaints"] = desiredTaints
		}
		if len(removed) > 0 {
			taints["removeTaints"] = removed
		}
		input["taints"] = taints
	}
	for _, key := range []string{"ScalingConfig", "UpdateConfig", "NodeRepairConfig", "WarmPoolConfig"} {
		if cfnComputeChanged(r.Previous, r.Properties, key) && r.Properties[key] != nil {
			input[key] = r.Properties[key]
		}
	}
	if len(input) == 2 {
		return false, nil
	}
	input["clientRequestToken"] = cfnCSClientToken(r, fmt.Sprintf("config/%v", input), 64)
	return true, cfnCSRun(ctx, h.commands, "eks", "UpdateNodegroupConfig", input)
}
func cfnCSSameSet(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for _, item := range a {
		found := false
		for _, other := range b {
			if reflect.DeepEqual(item, other) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (h cfnEKSNodegroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnEKSContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, name, err := cfnEKSNodegroupIdentity(r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	n, err := h.get(ctx, cluster, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEKSNodegroupResult(n)
	tags := cfnEKSTagMap(n.Tags)
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	if err := cfnEKSReconcileTags(ctx, h.commands, r, cfnComputeValue(n.NodegroupArn), tags, cfnEKSMapResourceTags(r)); err != nil {
		return result, err
	}
	if cfnComputeValue(n.Status) == "ACTIVE" {
		if pending, err := cfnEKSPending(ctx, h.commands, map[string]any{"name": cluster, "nodegroupName": name}); err != nil || pending {
			return result, nil
		}
		_, err = h.converge(ctx, r, n)
	}
	return result, err
}
func (h cfnEKSNodegroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnEKSContext(ctx, r)
	cluster, name, err := cfnEKSNodegroupIdentity(r.PhysicalID)
	if err != nil {
		return false, err
	}
	n, err := h.get(ctx, cluster, name)
	if err != nil {
		return false, err
	}
	switch status := cfnComputeValue(n.Status); status {
	case "ACTIVE":
	case "CREATE_FAILED", "DEGRADED", "DELETING", "DELETE_FAILED":
		return false, fmt.Errorf("EKS nodegroup %s is %s", r.PhysicalID, status)
	default:
		return false, nil
	}
	pending, err := cfnEKSPending(ctx, h.commands, map[string]any{"name": cluster, "nodegroupName": name})
	if err != nil || pending {
		return false, err
	}
	issued, err := h.converge(ctx, r, n)
	return !issued && err == nil, err
}
func (h cfnEKSNodegroup) locate(r cloudformation.ResourceRequest) (string, string) {
	if cluster, name, err := cfnEKSNodegroupIdentity(r.PhysicalID); err == nil {
		return cluster, name
	}
	return cfnComputeString(r.Properties, "ClusterName"), h.name(r)
}
func (h cfnEKSNodegroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		id, err := cfnEKSRecoveryID(ctx, h.commands, r)
		if cfnCSMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		r.PhysicalID = id
	}
	ctx = cfnEKSContext(ctx, r)
	cluster, name := h.locate(r)
	n, err := h.get(ctx, cluster, name)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(n.Status) == "DELETING" {
		return nil
	}
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eks", "DeleteNodegroup", map[string]any{"clusterName": cluster, "nodegroupName": name}))
}
func (h cfnEKSNodegroup) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnEKSContext(ctx, r)
	cluster, name := h.locate(r)
	n, err := h.get(ctx, cluster, name)
	if cfnCSMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if status := cfnComputeValue(n.Status); status == "DELETE_FAILED" {
		return false, fmt.Errorf("EKS nodegroup deletion failed")
	}
	return false, nil
}
func (h cfnEKSNodegroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	cluster, name, err := cfnEKSNodegroupIdentity(r.PhysicalID)
	if err != nil {
		return nil, err
	}
	n, err := h.get(ctx, cluster, name)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(n, map[string]string{"nodegroupArn": "Arn"}, "labels", "tags")
	if err != nil {
		return nil, err
	}
	p["Id"] = cluster + "/" + name
	tags := map[string]any{}
	for key, value := range cfnEKSTagMap(n.Tags) {
		tags[key] = value
	}
	p["Tags"] = tags
	return cfnCSKeep(p, "Id", "Arn", "ClusterName", "NodegroupName", "NodeRole", "Subnets", "AmiType", "CapacityType", "DiskSize", "InstanceTypes", "Labels", "LaunchTemplate", "ReleaseVersion", "RemoteAccess", "ScalingConfig", "Taints", "UpdateConfig", "NodeRepairConfig", "WarmPoolConfig", "Version", "Tags"), nil
}
func (h cfnEKSNodegroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return cfnEKSChildren(ctx, h.commands, "ListNodegroups", func(out *api.ListNodegroupsResponse) ([]api.String, *api.String) {
		return out.Nodegroups, out.NextToken
	}, func(cluster, name string) cloudformation.ResourceDescription {
		return cloudformation.ResourceDescription{Identifier: cluster + "/" + name, Properties: cloudformation.Properties{"Id": cluster + "/" + name, "ClusterName": cluster, "NodegroupName": name}}
	})
}
func cfnEKSChildren[T any](ctx context.Context, c StepFunctionsCommands, operation string, page func(*T) ([]api.String, *api.String), row func(string, string) cloudformation.ResourceDescription) ([]cloudformation.ResourceDescription, error) {
	clusters, err := cfnCSEKSClusters(ctx, c)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, cluster := range clusters {
		input := map[string]any{"clusterName": cluster}
		for {
			out, err := cfnComputeCall[T](ctx, c, "eks", operation, input)
			if cfnCSMissing(err) {
				break
			}
			if err != nil {
				return nil, err
			}
			names, next := page(out)
			for _, name := range names {
				rows = append(rows, row(cluster, string(name)))
			}
			if cfnComputeValue(next) == "" {
				break
			}
			input["nextToken"] = cfnComputeValue(next)
		}
	}
	return rows, nil
}

// ---- AWS::EKS::Addon ----

type cfnEKSAddon struct{ commands StepFunctionsCommands }

const cfnEKSAddonType = "AWS::EKS::Addon"

func (h cfnEKSAddon) Validate(p cloudformation.Properties) error {
	return cfnEKSValidate(cfnEKSAddonType, p)
}
func (h cfnEKSAddon) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnEKSAddonType, a, b)
}
func (h cfnEKSAddon) locate(r cloudformation.ResourceRequest) (string, string, error) {
	if r.PhysicalID != "" {
		parts, err := cfnCSCompound(r.PhysicalID, 2)
		if err != nil {
			return "", "", err
		}
		return parts[0], parts[1], nil
	}
	return cfnComputeString(r.Properties, "ClusterName"), cfnComputeString(r.Properties, "AddonName"), nil
}
func (h cfnEKSAddon) get(ctx context.Context, cluster, name string) (*api.Addon, error) {
	out, err := cfnComputeCall[api.DescribeAddonResponse](ctx, h.commands, "eks", "DescribeAddon", map[string]any{"clusterName": cluster, "addonName": name})
	if err != nil {
		return nil, err
	}
	return out.Addon, nil
}
func cfnEKSAddonResult(a *api.Addon) cloudformation.ResourceResult {
	id := cfnComputeValue(a.ClusterName) + "|" + cfnComputeValue(a.AddonName)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": cfnComputeValue(a.AddonArn)}}
}
func (h cfnEKSAddon) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, recoveryErr := cfnEKSRecoveryID(ctx, h.commands, r)
	if recoveryErr == nil {
		r.PhysicalID = id
	} else if !cfnCSMissing(recoveryErr) {
		return cloudformation.ResourceResult{}, recoveryErr
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, name, _ := h.locate(r)
	if a, err := h.get(ctx, cluster, name); err == nil {
		if err := cfnEKSOwned(ctx, h.commands, r, cfnEKSExpectedID(r)); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return cfnEKSAddonResult(a), nil
	} else if !cfnCSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnCSRename(r.Properties, nil, "Tags", "PreserveOnDelete")
	input["tags"] = cfnEKSResourceTags(r)
	input["clientRequestToken"] = cfnCSClientToken(r, "CreateAddon", 64)
	out, err := cfnCSCall[api.CreateAddonResponse](cfnEKSCreateContext(ctx, r), h.commands, "eks", "CreateAddon", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSAddonResult(out.Addon), nil
}
func (h cfnEKSAddon) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnEKSContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, name, err := h.locate(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	a, err := h.get(ctx, cluster, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEKSAddonResult(a)
	tags := cfnEKSTagMap(a.Tags)
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	mutable := []string{"AddonVersion", "ConfigurationValues", "PodIdentityAssociations", "ServiceAccountRoleArn", "ResolveConflicts"}
	if cfnComputeChanged(r.Previous, r.Properties, mutable...) {
		input := cfnComputeCopy(r.Properties, mutable...)
		input["clusterName"], input["addonName"] = cluster, name
		if _, ok := input["PodIdentityAssociations"]; !ok && r.Previous["PodIdentityAssociations"] != nil {
			input["PodIdentityAssociations"] = []any{}
		}
		if _, ok := input["ConfigurationValues"]; !ok && r.Previous["ConfigurationValues"] != nil {
			input["ConfigurationValues"] = ""
		}
		input["clientRequestToken"] = cfnCSClientToken(r, fmt.Sprintf("update/%v", input), 64)
		if err := cfnCSRun(ctx, h.commands, "eks", "UpdateAddon", input); err != nil {
			return result, err
		}
	}
	return result, cfnEKSReconcileTags(ctx, h.commands, r, cfnComputeValue(a.AddonArn), tags, cfnEKSResourceTags(r))
}
func (h cfnEKSAddon) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnEKSContext(ctx, r)
	cluster, name, err := h.locate(r)
	if err != nil {
		return false, err
	}
	a, err := h.get(ctx, cluster, name)
	if err != nil {
		return false, err
	}
	switch status := cfnComputeValue(a.Status); status {
	case "ACTIVE":
	case "CREATE_FAILED", "UPDATE_FAILED", "DEGRADED", "DELETING", "DELETE_FAILED":
		return false, fmt.Errorf("EKS add-on %s is %s", r.PhysicalID, status)
	default:
		return false, nil
	}
	pending, err := cfnEKSPending(ctx, h.commands, map[string]any{"name": cluster, "addonName": name})
	return !pending && err == nil, err
}
func (h cfnEKSAddon) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		id, err := cfnEKSRecoveryID(ctx, h.commands, r)
		if cfnCSMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		r.PhysicalID = id
	}
	ctx = cfnEKSContext(ctx, r)
	cluster, name, err := h.locate(r)
	if err != nil {
		return err
	}
	a, err := h.get(ctx, cluster, name)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(a.Status) == "DELETING" {
		return nil
	}
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return err
	}
	preserve, _ := r.Properties["PreserveOnDelete"].(bool)
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eks", "DeleteAddon", map[string]any{"clusterName": cluster, "addonName": name, "preserve": preserve}))
}
func (h cfnEKSAddon) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnEKSContext(ctx, r)
	cluster, name, err := h.locate(r)
	if err != nil {
		return false, err
	}
	a, err := h.get(ctx, cluster, name)
	if cfnCSMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if cfnComputeValue(a.Status) == "DELETE_FAILED" {
		return false, fmt.Errorf("EKS add-on deletion failed")
	}
	return false, nil
}
func (h cfnEKSAddon) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	cluster, name, err := h.locate(r)
	if err != nil {
		return nil, err
	}
	a, err := h.get(ctx, cluster, name)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(a, map[string]string{"addonArn": "Arn"}, "tags")
	if err != nil {
		return nil, err
	}
	if len(a.PodIdentityAssociations) > 0 {
		// The add-on response lists association ARNs; CloudFormation models
		// ServiceAccount/RoleArn pairs read from each owned association.
		var associations []any
		for _, arn := range a.PodIdentityAssociations {
			association, err := cfnEKSPodIdentity(h).describeArn(ctx, string(arn))
			if err != nil {
				return nil, err
			}
			associations = append(associations, map[string]any{"ServiceAccount": cfnComputeValue(association.ServiceAccount), "RoleArn": cfnComputeValue(association.RoleArn)})
		}
		p["PodIdentityAssociations"] = associations
	} else {
		delete(p, "PodIdentityAssociations")
	}
	p["Tags"] = cfnEKSPublicTags(cfnEKSTagMap(a.Tags))
	return cfnCSKeep(p, "ClusterName", "AddonName", "Arn", "AddonVersion", "ConfigurationValues", "ServiceAccountRoleArn", "PodIdentityAssociations", "NamespaceConfig", "Tags"), nil
}
func (h cfnEKSAddon) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return cfnEKSChildren(ctx, h.commands, "ListAddons", func(out *api.ListAddonsResponse) ([]api.String, *api.String) { return out.Addons, out.NextToken }, func(cluster, name string) cloudformation.ResourceDescription {
		return cloudformation.ResourceDescription{Identifier: cluster + "|" + name, Properties: cloudformation.Properties{"ClusterName": cluster, "AddonName": name}}
	})
}

// ---- AWS::EKS::FargateProfile ----

type cfnEKSFargateProfile struct{ commands StepFunctionsCommands }

const cfnEKSFargateProfileType = "AWS::EKS::FargateProfile"

func (h cfnEKSFargateProfile) Validate(p cloudformation.Properties) error {
	return cfnEKSValidate(cfnEKSFargateProfileType, p)
}
func (h cfnEKSFargateProfile) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnEKSFargateProfileType, a, b)
}
func (h cfnEKSFargateProfile) locate(r cloudformation.ResourceRequest) (string, string, error) {
	if r.PhysicalID != "" {
		parts, err := cfnCSCompound(r.PhysicalID, 2)
		if err != nil {
			return "", "", err
		}
		return parts[0], parts[1], nil
	}
	return cfnComputeString(r.Properties, "ClusterName"), cfnComputeName(r, "FargateProfileName", 100), nil
}
func (h cfnEKSFargateProfile) get(ctx context.Context, cluster, name string) (*api.FargateProfile, error) {
	out, err := cfnComputeCall[api.DescribeFargateProfileResponse](ctx, h.commands, "eks", "DescribeFargateProfile", map[string]any{"clusterName": cluster, "fargateProfileName": name})
	if err != nil {
		return nil, err
	}
	return out.FargateProfile, nil
}

// PhysicalID is the Cloud Control identifier; Ref is the documented
// cluster/profile physical name.
func cfnEKSFargateResult(f *api.FargateProfile) cloudformation.ResourceResult {
	cluster, name := cfnComputeValue(f.ClusterName), cfnComputeValue(f.FargateProfileName)
	return cloudformation.ResourceResult{PhysicalID: cluster + "|" + name, Ref: cluster + "/" + name, Attributes: map[string]any{"Arn": cfnComputeValue(f.FargateProfileArn)}}
}
func (h cfnEKSFargateProfile) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, recoveryErr := cfnEKSRecoveryID(ctx, h.commands, r)
	if recoveryErr == nil {
		r.PhysicalID = id
	} else if !cfnCSMissing(recoveryErr) {
		return cloudformation.ResourceResult{}, recoveryErr
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, name, _ := h.locate(r)
	if f, err := h.get(ctx, cluster, name); err == nil {
		if err := cfnEKSOwned(ctx, h.commands, r, cfnEKSExpectedID(r)); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		return cfnEKSFargateResult(f), nil
	} else if !cfnCSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnCSRename(r.Properties, nil, "Tags", "FargateProfileName")
	input["fargateProfileName"] = name
	input["tags"] = cfnEKSResourceTags(r)
	input["clientRequestToken"] = cfnCSClientToken(r, "CreateFargateProfile", 64)
	cfnEKSFargateSelectors(input)
	out, err := cfnCSCall[api.CreateFargateProfileResponse](cfnEKSCreateContext(ctx, r), h.commands, "eks", "CreateFargateProfile", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSFargateResult(out.FargateProfile), nil
}
func (h cfnEKSFargateProfile) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnEKSContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, name, err := h.locate(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	f, err := h.get(ctx, cluster, name)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEKSFargateResult(f)
	tags := cfnEKSTagMap(f.Tags)
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	return result, cfnEKSReconcileTags(ctx, h.commands, r, cfnComputeValue(f.FargateProfileArn), tags, cfnEKSResourceTags(r))
}
func (h cfnEKSFargateProfile) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnEKSContext(ctx, r)
	cluster, name, err := h.locate(r)
	if err != nil {
		return false, err
	}
	f, err := h.get(ctx, cluster, name)
	if err != nil {
		return false, err
	}
	switch status := cfnComputeValue(f.Status); status {
	case "ACTIVE":
		return true, nil
	case "CREATING":
		return false, nil
	default:
		return false, fmt.Errorf("EKS Fargate profile %s is %s", r.PhysicalID, status)
	}
}
func (h cfnEKSFargateProfile) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		id, err := cfnEKSRecoveryID(ctx, h.commands, r)
		if cfnCSMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		r.PhysicalID = id
	}
	ctx = cfnEKSContext(ctx, r)
	cluster, name, err := h.locate(r)
	if err != nil {
		return err
	}
	f, err := h.get(ctx, cluster, name)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(f.Status) == "DELETING" {
		return nil
	}
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eks", "DeleteFargateProfile", map[string]any{"clusterName": cluster, "fargateProfileName": name}))
}
func (h cfnEKSFargateProfile) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnEKSContext(ctx, r)
	cluster, name, err := h.locate(r)
	if err != nil {
		return false, err
	}
	f, err := h.get(ctx, cluster, name)
	if cfnCSMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if cfnComputeValue(f.Status) == "DELETE_FAILED" {
		return false, fmt.Errorf("EKS Fargate profile deletion failed")
	}
	return false, nil
}
func (h cfnEKSFargateProfile) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	cluster, name, err := h.locate(r)
	if err != nil {
		return nil, err
	}
	f, err := h.get(ctx, cluster, name)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(f, map[string]string{"fargateProfileArn": "Arn"}, "tags", "labels")
	if err != nil {
		return nil, err
	}
	if selectors, ok := p["Selectors"].([]any); ok {
		for _, raw := range selectors {
			// Selector labels are customer keys; CloudFormation lists them as Key/Value.
			selector, _ := raw.(map[string]any)
			if labels, ok := selector["Labels"].(map[string]any); ok {
				list := []any{}
				for _, key := range slices.Sorted(maps.Keys(labels)) {
					list = append(list, map[string]any{"Key": key, "Value": labels[key]})
				}
				selector["Labels"] = list
			}
		}
	}
	p["Tags"] = cfnEKSPublicTags(cfnEKSTagMap(f.Tags))
	return cfnCSKeep(p, "ClusterName", "FargateProfileName", "Arn", "PodExecutionRoleArn", "Subnets", "Selectors", "Tags"), nil
}
func (h cfnEKSFargateProfile) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return cfnEKSChildren(ctx, h.commands, "ListFargateProfiles", func(out *api.ListFargateProfilesResponse) ([]api.String, *api.String) {
		return out.FargateProfileNames, out.NextToken
	}, func(cluster, name string) cloudformation.ResourceDescription {
		return cloudformation.ResourceDescription{Identifier: cluster + "|" + name, Properties: cloudformation.Properties{"ClusterName": cluster, "FargateProfileName": name}}
	})
}

// cfnEKSFargateSelectors converts CloudFormation selector label lists to the
// owner's label maps before strict binding.
func cfnEKSFargateSelectors(p map[string]any) {
	selectors, _ := p["Selectors"].([]any)
	out := make([]any, 0, len(selectors))
	for _, raw := range selectors {
		selector, ok := cfnComputeObject(raw)
		if !ok {
			out = append(out, raw)
			continue
		}
		selector = maps.Clone(selector)
		if labels, ok := selector["Labels"].([]any); ok {
			converted := map[string]any{}
			for _, item := range labels {
				label, _ := cfnComputeObject(item)
				if key, ok := label["Key"].(string); ok {
					converted[key] = label["Value"]
				}
			}
			selector["Labels"] = converted
		}
		out = append(out, selector)
	}
	if selectors != nil {
		p["Selectors"] = out
	}
}

// ---- AWS::EKS::AccessEntry ----

type cfnEKSAccessEntry struct{ commands StepFunctionsCommands }

const cfnEKSAccessEntryType = "AWS::EKS::AccessEntry"

func (h cfnEKSAccessEntry) Validate(p cloudformation.Properties) error {
	return cfnEKSValidate(cfnEKSAccessEntryType, p)
}
func (h cfnEKSAccessEntry) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnEKSAccessEntryType, a, b)
}
func (h cfnEKSAccessEntry) locate(r cloudformation.ResourceRequest) (string, string, error) {
	if r.PhysicalID != "" {
		parts, err := cfnCSCompound(r.PhysicalID, 2)
		if err != nil {
			return "", "", err
		}
		return parts[1], parts[0], nil
	}
	return cfnComputeString(r.Properties, "ClusterName"), cfnComputeString(r.Properties, "PrincipalArn"), nil
}
func (h cfnEKSAccessEntry) get(ctx context.Context, cluster, principal string) (*api.AccessEntry, error) {
	out, err := cfnComputeCall[api.DescribeAccessEntryResponse](ctx, h.commands, "eks", "DescribeAccessEntry", map[string]any{"clusterName": cluster, "principalArn": principal})
	if err != nil {
		return nil, err
	}
	return out.AccessEntry, nil
}
func cfnEKSAccessResult(e *api.AccessEntry) cloudformation.ResourceResult {
	arn := cfnComputeValue(e.AccessEntryArn)
	return cloudformation.ResourceResult{PhysicalID: cfnComputeValue(e.PrincipalArn) + "|" + cfnComputeValue(e.ClusterName), Ref: arn, Attributes: map[string]any{"AccessEntryArn": arn}}
}
func (h cfnEKSAccessEntry) policies(ctx context.Context, cluster, principal string) ([]any, error) {
	var out []any
	input := map[string]any{"clusterName": cluster, "principalArn": principal}
	for {
		page, err := cfnComputeCall[api.ListAssociatedAccessPoliciesResponse](ctx, h.commands, "eks", "ListAssociatedAccessPolicies", input)
		if err != nil {
			return nil, err
		}
		for _, policy := range page.AssociatedAccessPolicies {
			item := map[string]any{"PolicyArn": cfnComputeValue(policy.PolicyArn)}
			if policy.AccessScope != nil {
				scope := map[string]any{"Type": cfnComputeValue(policy.AccessScope.Type)}
				if len(policy.AccessScope.Namespaces) > 0 {
					namespaces := make([]any, len(policy.AccessScope.Namespaces))
					for i, ns := range policy.AccessScope.Namespaces {
						namespaces[i] = string(ns)
					}
					scope["Namespaces"] = namespaces
				}
				item["AccessScope"] = scope
			}
			out = append(out, item)
		}
		if cfnComputeValue(page.NextToken) == "" {
			return out, nil
		}
		input["nextToken"] = cfnComputeValue(page.NextToken)
	}
}

// reconcilePolicies associates desired policies and disassociates removed ones.
func (h cfnEKSAccessEntry) reconcilePolicies(ctx context.Context, r cloudformation.ResourceRequest, cluster, principal string) error {
	desired, _ := r.Properties["AccessPolicies"].([]any)
	current, err := h.policies(ctx, cluster, principal)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, raw := range desired {
		policy, _ := cfnComputeObject(raw)
		arn, _ := policy["PolicyArn"].(string)
		wanted[arn] = true
		found := false
		for _, item := range current {
			existing, _ := item.(map[string]any)
			if existing["PolicyArn"] == arn && reflect.DeepEqual(cfnCSNormalizedScope(existing["AccessScope"]), cfnCSNormalizedScope(policy["AccessScope"])) {
				found = true
			}
		}
		if found {
			continue
		}
		if err := cfnCSRun(ctx, h.commands, "eks", "AssociateAccessPolicy", map[string]any{"clusterName": cluster, "principalArn": principal, "policyArn": arn, "accessScope": policy["AccessScope"]}); err != nil {
			return err
		}
	}
	for _, item := range current {
		existing, _ := item.(map[string]any)
		arn, _ := existing["PolicyArn"].(string)
		if wanted[arn] {
			continue
		}
		if err := cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eks", "DisassociateAccessPolicy", map[string]any{"clusterName": cluster, "principalArn": principal, "policyArn": arn})); err != nil {
			return err
		}
	}
	return nil
}
func cfnCSNormalizedScope(v any) any {
	scope, _ := cfnComputeObject(v)
	namespaces, _ := scope["Namespaces"].([]any)
	names := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		names = append(names, fmt.Sprint(ns))
	}
	sort.Strings(names)
	return fmt.Sprint(scope["Type"], names)
}
func (h cfnEKSAccessEntry) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, recoveryErr := cfnEKSRecoveryID(ctx, h.commands, r)
	if recoveryErr == nil {
		r.PhysicalID = id
	} else if !cfnCSMissing(recoveryErr) {
		return cloudformation.ResourceResult{}, recoveryErr
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, principal, _ := h.locate(r)
	entry, err := h.get(ctx, cluster, principal)
	if err == nil {
		if err := cfnEKSOwned(ctx, h.commands, r, cfnEKSExpectedID(r)); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
	} else if !cfnCSMissing(err) {
		return cloudformation.ResourceResult{}, err
	} else {
		input := cfnCSRename(r.Properties, nil, "Tags", "AccessPolicies")
		input["tags"] = cfnEKSResourceTags(r)
		input["clientRequestToken"] = cfnCSClientToken(r, "CreateAccessEntry", 64)
		out, err := cfnCSCall[api.CreateAccessEntryResponse](cfnEKSCreateContext(ctx, r), h.commands, "eks", "CreateAccessEntry", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		entry = out.AccessEntry
	}
	result := cfnEKSAccessResult(entry)
	r.PhysicalID = result.PhysicalID
	return result, h.reconcilePolicies(cfnEKSContext(ctx, r), r, cluster, principal)
}
func (h cfnEKSAccessEntry) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnEKSContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	cluster, principal, err := h.locate(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	entry, err := h.get(ctx, cluster, principal)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEKSAccessResult(entry)
	tags := cfnEKSTagMap(entry.Tags)
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "KubernetesGroups", "Username") {
		input := map[string]any{"clusterName": cluster, "principalArn": principal, "kubernetesGroups": cfnComputeDefault(r.Properties, "KubernetesGroups", []any{})}
		if username, ok := r.Properties["Username"]; ok {
			input["username"] = username
		}
		if err := cfnCSRun(ctx, h.commands, "eks", "UpdateAccessEntry", input); err != nil {
			return result, err
		}
	}
	if err := h.reconcilePolicies(ctx, r, cluster, principal); err != nil {
		return result, err
	}
	return result, cfnEKSReconcileTags(ctx, h.commands, r, cfnComputeValue(entry.AccessEntryArn), tags, cfnEKSResourceTags(r))
}
func (h cfnEKSAccessEntry) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		id, err := cfnEKSRecoveryID(ctx, h.commands, r)
		if cfnCSMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		r.PhysicalID = id
	}
	ctx = cfnEKSContext(ctx, r)
	cluster, principal, err := h.locate(r)
	if err != nil {
		return err
	}
	_, err = h.get(ctx, cluster, principal)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eks", "DeleteAccessEntry", map[string]any{"clusterName": cluster, "principalArn": principal}))
}
func (h cfnEKSAccessEntry) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	cluster, principal, err := h.locate(r)
	if err != nil {
		return nil, err
	}
	entry, err := h.get(ctx, cluster, principal)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(entry, nil, "tags")
	if err != nil {
		return nil, err
	}
	if p["AccessPolicies"], err = h.policies(ctx, cluster, principal); err != nil {
		return nil, err
	}
	p["Tags"] = cfnEKSPublicTags(cfnEKSTagMap(entry.Tags))
	return cfnCSKeep(p, "ClusterName", "PrincipalArn", "AccessEntryArn", "Username", "KubernetesGroups", "Type", "AccessPolicies", "Tags"), nil
}
func (h cfnEKSAccessEntry) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return cfnEKSChildren(ctx, h.commands, "ListAccessEntries", func(out *api.ListAccessEntriesResponse) ([]api.String, *api.String) {
		return out.AccessEntries, out.NextToken
	}, func(cluster, principal string) cloudformation.ResourceDescription {
		return cloudformation.ResourceDescription{Identifier: principal + "|" + cluster, Properties: cloudformation.Properties{"ClusterName": cluster, "PrincipalArn": principal}}
	})
}

// ---- AWS::EKS::PodIdentityAssociation ----

type cfnEKSPodIdentity struct{ commands StepFunctionsCommands }

const cfnEKSPodIdentityType = "AWS::EKS::PodIdentityAssociation"

func (h cfnEKSPodIdentity) Validate(p cloudformation.Properties) error {
	return cfnEKSValidate(cfnEKSPodIdentityType, p)
}
func (h cfnEKSPodIdentity) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnCSReplacement(cfnEKSPodIdentityType, a, b)
}

// arn:<partition>:eks:<region>:<account>:podidentityassociation/<cluster>/<id>
func cfnEKSPodIdentityARN(arn string) (string, string, error) {
	_, resource, ok := strings.Cut(arn, ":podidentityassociation/")
	cluster, id, qualified := strings.Cut(resource, "/")
	if !ok || !qualified || cluster == "" || id == "" {
		return "", "", fmt.Errorf("invalid EKS Pod Identity association ARN %q", arn)
	}
	return cluster, id, nil
}
func (h cfnEKSPodIdentity) describe(ctx context.Context, cluster, id string) (*api.PodIdentityAssociation, error) {
	out, err := cfnComputeCall[api.DescribePodIdentityAssociationResponse](ctx, h.commands, "eks", "DescribePodIdentityAssociation", map[string]any{"clusterName": cluster, "associationId": id})
	if err != nil {
		return nil, err
	}
	return out.Association, nil
}
func (h cfnEKSPodIdentity) describeArn(ctx context.Context, arn string) (*api.PodIdentityAssociation, error) {
	cluster, id, err := cfnEKSPodIdentityARN(arn)
	if err != nil {
		return nil, err
	}
	metadata := awsctx.FromContext(ctx)
	expected := "arn:" + metadata.Partition + ":eks:" + metadata.Region + ":" + metadata.AccountID + ":podidentityassociation/" + cluster + "/" + id
	if arn != expected {
		return nil, fmt.Errorf("EKS Pod Identity association ARN is outside the current request scope")
	}
	return h.describe(ctx, cluster, id)
}
func cfnEKSPodIdentityResult(a *api.PodIdentityAssociation) cloudformation.ResourceResult {
	arn := cfnComputeValue(a.AssociationArn)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: cfnComputeValue(a.AssociationId), Attributes: map[string]any{"AssociationArn": arn, "AssociationId": cfnComputeValue(a.AssociationId), "ExternalId": cfnComputeValue(a.ExternalId)}}
}

func (h cfnEKSPodIdentity) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, recoveryErr := cfnEKSRecoveryID(ctx, h.commands, r)
	if recoveryErr == nil {
		r.PhysicalID = id
	} else if !cfnCSMissing(recoveryErr) {
		return cloudformation.ResourceResult{}, recoveryErr
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if r.PhysicalID != "" {
		association, err := h.describeArn(cfnEKSContext(ctx, r), r.PhysicalID)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnEKSPodIdentityResult(association), nil
	}
	input := cfnCSRename(r.Properties, nil, "Tags")
	input["tags"] = cfnEKSResourceTags(r)
	input["clientRequestToken"] = cfnCSClientToken(r, "CreatePodIdentityAssociation", 64)
	out, err := cfnCSCall[api.CreatePodIdentityAssociationResponse](cfnEKSCreateContext(ctx, r), h.commands, "eks", "CreatePodIdentityAssociation", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEKSPodIdentityResult(out.Association), nil
}
func (h cfnEKSPodIdentity) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnEKSContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	association, err := h.describeArn(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEKSPodIdentityResult(association)
	tags := cfnEKSTagMap(association.Tags)
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	mutable := []string{"RoleArn", "TargetRoleArn", "Policy", "DisableSessionTags"}
	if cfnComputeChanged(r.Previous, r.Properties, mutable...) {
		input := cfnComputeCopy(r.Properties, mutable...)
		input["clusterName"], input["associationId"] = cfnComputeValue(association.ClusterName), cfnComputeValue(association.AssociationId)
		if _, ok := input["TargetRoleArn"]; !ok && r.Previous["TargetRoleArn"] != nil {
			input["TargetRoleArn"] = ""
		}
		if _, ok := input["Policy"]; !ok && r.Previous["Policy"] != nil {
			input["Policy"] = ""
		}
		input["clientRequestToken"] = cfnCSClientToken(r, fmt.Sprintf("update/%v", input), 64)
		out, err := cfnCSCall[api.UpdatePodIdentityAssociationResponse](ctx, h.commands, "eks", "UpdatePodIdentityAssociation", input)
		if err != nil {
			return result, err
		}
		result = cfnEKSPodIdentityResult(out.Association)
	}
	return result, cfnEKSReconcileTags(ctx, h.commands, r, r.PhysicalID, tags, cfnEKSResourceTags(r))
}
func (h cfnEKSPodIdentity) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		id, err := cfnEKSRecoveryID(ctx, h.commands, r)
		if cfnCSMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		r.PhysicalID = id
	}
	ctx = cfnEKSContext(ctx, r)
	association, err := h.describeArn(ctx, r.PhysicalID)
	if cfnCSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnEKSOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "eks", "DeletePodIdentityAssociation", map[string]any{"clusterName": cfnComputeValue(association.ClusterName), "associationId": cfnComputeValue(association.AssociationId)}))
}
func (h cfnEKSPodIdentity) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	association, err := h.describeArn(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnCSProject(association, nil, "tags")
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnEKSPublicTags(cfnEKSTagMap(association.Tags))
	return cfnCSKeep(p, "AssociationArn", "AssociationId", "ClusterName", "Namespace", "ServiceAccount", "RoleArn", "TargetRoleArn", "Policy", "DisableSessionTags", "ExternalId", "Tags"), nil
}
func (h cfnEKSPodIdentity) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	clusters, err := cfnCSEKSClusters(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, cluster := range clusters {
		input := map[string]any{"clusterName": cluster}
		for {
			out, err := cfnComputeCall[api.ListPodIdentityAssociationsResponse](ctx, h.commands, "eks", "ListPodIdentityAssociations", input)
			if cfnCSMissing(err) {
				break
			}
			if err != nil {
				return nil, err
			}
			for _, summary := range out.Associations {
				arn := cfnComputeValue(summary.AssociationArn)
				rows = append(rows, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"AssociationArn": arn, "ClusterName": cluster}})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["nextToken"] = cfnComputeValue(out.NextToken)
		}
	}
	return rows, nil
}
