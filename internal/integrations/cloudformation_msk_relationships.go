package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/kafka"
	"stackd/internal/services/cloudformation"
)

func cfnMSKEdgeKey(slot string) string { return cfnComputeTagPrefix + "edge-msk-" + slot }
func cfnMSKEdgeOwned(r cloudformation.ResourceRequest, tags map[string]string, slot string) error {
	if r.CloudControl {
		return nil
	}
	if tags[cfnMSKEdgeKey(slot)] != cfnEngineEdgeOwner(r) {
		return fmt.Errorf("MSK %s relationship is not owned by this resource incarnation", slot)
	}
	return nil
}
func cfnMSKEdgeClaim(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, slot string, tags map[string]string) error {
	key := cfnMSKEdgeKey(slot)
	if existing := tags[key]; existing != "" && existing != cfnEngineEdgeOwner(r) {
		return cfnResourceCreateOwnedError(r, fmt.Errorf("MSK %s relationship is already owned", slot))
	}
	return cfnComputeRun(ctx, c, "kafka", "TagResource", map[string]any{"ResourceArn": cfnComputeString(r.Properties, "ClusterArn"), "tags": map[string]string{key: cfnEngineEdgeOwner(r)}})
}
func cfnMSKEdgeRelease(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, slot string) error {
	return cfnComputeRun(ctx, c, "kafka", "UntagResource", map[string]any{"ResourceArn": r.PhysicalID, "tagKeys": []string{cfnMSKEdgeKey(slot)}})
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-msk-batchscramsecret.html
type cfnMSKBatchScramSecret struct{ commands StepFunctionsCommands }

func (h cfnMSKBatchScramSecret) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ClusterArn", "SecretArnList"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ClusterArn"); err != nil {
		return err
	}
	_, err := cfnComputeStringList(p, "SecretArnList")
	return err
}
func (h cfnMSKBatchScramSecret) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ClusterArn"), h.Validate(b)
}
func (h cfnMSKBatchScramSecret) secrets(ctx context.Context, arn string) ([]string, error) {
	result := []string{}
	input := map[string]any{"ClusterArn": arn}
	for {
		out, err := cfnComputeCall[api.ListScramSecretsOutput](ctx, h.commands, "kafka", "ListScramSecrets", input)
		if err != nil {
			return nil, err
		}
		result = append(result, cfnEngineList(out.SecretArnList)...)
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnMSKBatchScramSecret) associate(ctx context.Context, arn string, secrets []string, remove bool) error {
	// MSK admits at most ten secrets per batch. Further batches continue only
	// after the native broker operation stabilizes, not during a busy fleet.
	if len(secrets) > 10 {
		secrets = secrets[:10]
	}
	if len(secrets) == 0 {
		return nil
	}
	input := map[string]any{"ClusterArn": arn, "secretArnList": secrets}
	if remove {
		out, err := cfnComputeCall[api.BatchDisassociateScramSecretOutput](ctx, h.commands, "kafka", "BatchDisassociateScramSecret", input)
		if err != nil {
			return err
		}
		for _, e := range out.UnprocessedScramSecrets {
			return fmt.Errorf("SCRAM disassociation failed: %s: %s", cfnComputeValue(e.ErrorCode), cfnComputeValue(e.ErrorMessage))
		}
		return nil
	}
	out, err := cfnComputeCall[api.BatchAssociateScramSecretOutput](ctx, h.commands, "kafka", "BatchAssociateScramSecret", input)
	if err != nil {
		return err
	}
	for _, e := range out.UnprocessedScramSecrets {
		return fmt.Errorf("SCRAM association failed: %s: %s", cfnComputeValue(e.ErrorCode), cfnComputeValue(e.ErrorMessage))
	}
	return nil
}
func (h cfnMSKBatchScramSecret) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = cfnComputeString(r.Properties, "ClusterArn")
	v, err := (cfnMSKCluster(h)).get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags := cfnMSKTags(v.Tags)
	current, err := h.secrets(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	desired, _ := cfnComputeStringList(r.Properties, "SecretArnList")
	if tags[cfnMSKEdgeKey("scram")] == "" {
		existing := cfnEngineSet(current)
		for _, secret := range desired {
			if existing[secret] {
				return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("SCRAM secret association already exists outside this resource"))
			}
		}
	}
	if err = cfnMSKEdgeClaim(ctx, h.commands, r, "scram", tags); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	add, _ := cfnEngineDifference(current, desired)
	if err = h.associate(ctx, r.PhysicalID, add, false); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnMSKBatchScramSecret) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	v, err := (cfnMSKCluster(h)).get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if err = cfnMSKEdgeOwned(r, cfnMSKTags(v.Tags), "scram"); err != nil {
		return result, err
	}
	ready, err := h.Stabilize(ctx, r)
	if err != nil {
		return result, err
	}
	if !ready {
		return result, nil
	}
	return h.Result(ctx, r)
}
func (h cfnMSKBatchScramSecret) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	arn := r.PhysicalID
	if arn == "" {
		arn = cfnComputeString(r.Properties, "ClusterArn")
		r.PhysicalID = arn
	}
	v, err := (cfnMSKCluster(h)).get(ctx, arn)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	tags := cfnMSKTags(v.Tags)
	if !r.CloudControl && tags[cfnMSKEdgeKey("scram")] == "" {
		return nil
	}
	if err = cfnMSKEdgeOwned(r, tags, "scram"); err != nil {
		return err
	}
	if cfnComputeValue(v.State) != "ACTIVE" && cfnComputeValue(v.State) != "FAILED" {
		return nil
	}
	desired, _ := cfnComputeStringList(r.Properties, "SecretArnList")
	current, err := h.secrets(ctx, arn)
	if err != nil {
		return err
	}
	present := cfnEngineSet(current)
	remove := []string{}
	for _, secret := range desired {
		if present[secret] {
			remove = append(remove, secret)
		}
	}
	return h.associate(ctx, arn, remove, true)
}
func (h cfnMSKBatchScramSecret) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	secrets, err := h.secrets(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return cloudformation.Properties{"ClusterArn": r.PhysicalID, "SecretArnList": secrets}, nil
}
func (h cfnMSKBatchScramSecret) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	clusters, err := (cfnMSKCluster(h)).List(ctx, r)
	if err != nil {
		return nil, err
	}
	result := []cloudformation.ResourceDescription{}
	for _, cluster := range clusters {
		r.PhysicalID = cluster.Identifier
		p, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		if len(p["SecretArnList"].([]string)) > 0 {
			result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
	}
	return result, nil
}
func (h cfnMSKBatchScramSecret) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := (cfnMSKCluster(h)).get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	ready, err := cfnEngineStable(cfnComputeValue(v.State), "ACTIVE")
	if !ready || err != nil {
		return ready, err
	}
	if err = cfnMSKEdgeOwned(r, cfnMSKTags(v.Tags), "scram"); err != nil {
		return false, err
	}
	current, err := h.secrets(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	desired, _ := cfnComputeStringList(r.Properties, "SecretArnList")
	previous, _ := cfnComputeStringList(r.Previous, "SecretArnList")
	_, removed := cfnEngineDifference(previous, desired)
	present := cfnEngineSet(current)
	remove := []string{}
	for _, secret := range removed {
		if present[secret] {
			remove = append(remove, secret)
		}
	}
	if len(remove) > 0 {
		err = h.associate(ctx, r.PhysicalID, remove, true)
		return false, err
	}
	add, _ := cfnEngineDifference(current, desired)
	if len(add) > 0 {
		err = h.associate(ctx, r.PhysicalID, add, false)
		return false, err
	}
	return true, nil
}
func (h cfnMSKBatchScramSecret) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := (cfnMSKCluster(h)).get(ctx, r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	ready, err := cfnEngineStable(cfnComputeValue(v.State), "ACTIVE")
	if !ready || err != nil {
		return ready, err
	}
	current, err := h.secrets(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	present := cfnEngineSet(current)
	desired, _ := cfnComputeStringList(r.Properties, "SecretArnList")
	for _, secret := range desired {
		if present[secret] {
			return false, h.Delete(ctx, r)
		}
	}
	if !r.CloudControl {
		if cfnMSKTags(v.Tags)[cfnMSKEdgeKey("scram")] == "" {
			return true, nil
		}
		if err = cfnMSKEdgeOwned(r, cfnMSKTags(v.Tags), "scram"); err != nil {
			return false, err
		}
		err = cfnMSKEdgeRelease(ctx, h.commands, r, "scram")
	}
	return err == nil, err
}
func (h cfnMSKBatchScramSecret) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-msk-clusterpolicy.html
type cfnMSKClusterPolicy struct{ commands StepFunctionsCommands }

func (h cfnMSKClusterPolicy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ClusterArn", "Policy"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ClusterArn", "Policy"); err != nil {
		return err
	}
	_, err := cfnComputeDocument(p["Policy"])
	return err
}
func (h cfnMSKClusterPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ClusterArn"), h.Validate(b)
}
func (h cfnMSKClusterPolicy) get(ctx context.Context, arn string) (*api.GetClusterPolicyOutput, error) {
	return cfnComputeCall[api.GetClusterPolicyOutput](ctx, h.commands, "kafka", "GetClusterPolicy", map[string]any{"ClusterArn": arn})
}
func (h cfnMSKClusterPolicy) apply(ctx context.Context, r cloudformation.ResourceRequest, version string) error {
	policy, err := cfnComputeDocument(r.Properties["Policy"])
	if err != nil {
		return err
	}
	input := map[string]any{"ClusterArn": r.PhysicalID, "policy": policy}
	if version != "" {
		input["currentVersion"] = version
	}
	return cfnComputeRun(ctx, h.commands, "kafka", "PutClusterPolicy", input)
}
func (h cfnMSKClusterPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = cfnComputeString(r.Properties, "ClusterArn")
	v, err := (cfnMSKCluster(h)).get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags := cfnMSKTags(v.Tags)
	policy, err := h.get(ctx, r.PhysicalID)
	version := ""
	if err == nil {
		version = cfnComputeValue(policy.CurrentVersion)
		if tags[cfnMSKEdgeKey("policy")] == "" {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("cluster policy already exists outside this resource"))
		}
	} else if !cfnEngineMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnMSKEdgeClaim(ctx, h.commands, r, "policy", tags); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err = h.apply(ctx, r, version); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnMSKClusterPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	v, err := (cfnMSKCluster(h)).get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	if err = cfnMSKEdgeOwned(r, cfnMSKTags(v.Tags), "policy"); err != nil {
		return result, err
	}
	policy, err := h.get(ctx, r.PhysicalID)
	version := ""
	if err == nil {
		version = cfnComputeValue(policy.CurrentVersion)
	} else if !cfnEngineMissing(err) {
		return result, err
	}
	if err = h.apply(ctx, r, version); err != nil {
		return result, err
	}
	return h.Result(ctx, r)
}
func (h cfnMSKClusterPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		r.PhysicalID = cfnComputeString(r.Properties, "ClusterArn")
	}
	v, err := (cfnMSKCluster(h)).get(ctx, r.PhysicalID)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	tags := cfnMSKTags(v.Tags)
	if !r.CloudControl && tags[cfnMSKEdgeKey("policy")] == "" {
		return nil
	}
	if err = cfnMSKEdgeOwned(r, tags, "policy"); err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "kafka", "DeleteClusterPolicy", map[string]any{"ClusterArn": r.PhysicalID})
	if err != nil && !cfnEngineMissing(err) {
		return err
	}
	if !r.CloudControl {
		return cfnMSKEdgeRelease(ctx, h.commands, r, "policy")
	}
	return nil
}
func (h cfnMSKClusterPolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	var policy any
	if err = json.Unmarshal([]byte(cfnComputeValue(out.Policy)), &policy); err != nil {
		return nil, err
	}
	return cloudformation.Properties{"ClusterArn": r.PhysicalID, "Policy": policy, "CurrentVersion": cfnComputeValue(out.CurrentVersion)}, nil
}
func (h cfnMSKClusterPolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	clusters, err := (cfnMSKCluster(h)).List(ctx, r)
	if err != nil {
		return nil, err
	}
	result := []cloudformation.ResourceDescription{}
	for _, cluster := range clusters {
		r.PhysicalID = cluster.Identifier
		p, err := h.Read(ctx, r)
		if cfnEngineMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
	}
	return result, nil
}
func (h cfnMSKClusterPolicy) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}
