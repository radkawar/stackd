package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	legacyapi "stackd/internal/awsapi/es"
	api "stackd/internal/awsapi/opensearch"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/opensearch"
	"strings"
)

// cfnSearchCreateContext binds the exact private incarnation claim persisted
// on the native domain row. Create and RecoverCreation always use it, including
// Cloud Control creates, so no request can adopt a same-name foreign domain.
func cfnSearchCreateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return opensearch.WithCloudFormationOwner(ctx, cfnMessagingMarker(r))
}

// cfnSearchContext fences stack-owned commands to the exact incarnation. Cloud
// Control reads and mutations use only the current caller's native IAM.
func cfnSearchContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return cfnSearchCreateContext(ctx, r)
}

// cfnSearchAdmitted keeps an admitted domain identity when a later read fails.
func cfnSearchAdmitted(id, ref string, result cloudformation.ResourceResult, err error) (cloudformation.ResourceResult, error) {
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: id, Ref: ref}, err
	}
	return result, nil
}

// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-opensearchservice-domain.html
type cfnOpenSearchDomain struct{ commands StepFunctionsCommands }

func (h cfnOpenSearchDomain) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "DomainName", "EngineVersion", "AccessPolicies", "AdvancedOptions", "ClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions", "Tags"); err != nil {
		return err
	}
	if p["AccessPolicies"] != nil {
		if _, err := cfnComputeDocument(p["AccessPolicies"]); err != nil {
			return err
		}
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnOpenSearchDomain) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DomainName", "EngineVersion", "ClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions"), h.Validate(b)
}
func (h cfnOpenSearchDomain) get(ctx context.Context, name string) (*api.DomainStatus, error) {
	out, err := cfnComputeCall[api.DescribeDomainOutput](ctx, h.commands, "opensearch", "DescribeDomain", map[string]any{"DomainName": name})
	if err != nil {
		return nil, err
	}
	if out.DomainStatus == nil {
		return nil, fmt.Errorf("domain owner returned no status")
	}
	return out.DomainStatus, nil
}
func (h cfnOpenSearchDomain) tags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsOutput](ctx, h.commands, "opensearch", "ListTags", map[string]any{"ARN": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, t := range out.TagList {
		tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return tags, nil
}
func (h cfnOpenSearchDomain) updateTags(ctx context.Context, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	desired := cfnResourceTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, h.commands, "opensearch", "RemoveTags", map[string]any{"ARN": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, h.commands, "opensearch", "AddTags", map[string]any{"ARN": arn, "TagList": cfnComputeTagList(desired)})
}
func (h cfnOpenSearchDomain) input(p cloudformation.Properties) (map[string]any, error) {
	input := cfnComputeCopy(p, "DomainName", "EngineVersion", "AdvancedOptions", "ClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions")
	if p["AccessPolicies"] != nil {
		policy, err := cfnComputeDocument(p["AccessPolicies"])
		if err != nil {
			return nil, err
		}
		input["AccessPolicies"] = policy
	}
	return input, nil
}
func (h cfnOpenSearchDomain) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSearchCreateContext(ctx, r)
	name := cfnEngineName(r, "DomainName", 28)
	r.PhysicalID = name
	// Only this exact incarnation's private claim is observable here; a
	// same-name domain owned by anything else is absent and CreateDomain conflicts.
	if _, err := h.get(ctx, name); err == nil {
		result, err := h.Result(ctx, r)
		return cfnSearchAdmitted(name, name, result, err)
	} else if !cfnEngineMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input, err := h.input(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input["DomainName"] = name
	input["TagList"] = cfnComputeTagList(cfnResourceTags(r))
	if err = cfnComputeRun(ctx, h.commands, "opensearch", "CreateDomain", input); err != nil {
		// A modeled error may follow a committed admission whose reply was lost.
		if _, readErr := h.get(ctx, name); readErr == nil {
			return cloudformation.ResourceResult{PhysicalID: name, Ref: name}, err
		}
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.Result(ctx, r)
	return cfnSearchAdmitted(name, name, result, err)
}
func (h cfnOpenSearchDomain) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnSearchCreateContext(ctx, r)
	name := cfnEngineName(r, "DomainName", 28)
	r.PhysicalID = name
	if _, err := h.get(ctx, name); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.Result(ctx, r)
	return cfnSearchAdmitted(name, name, result, err)
}
func (h cfnOpenSearchDomain) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	ctx = cfnSearchContext(ctx, r)
	replacement, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replacement {
		return result, fmt.Errorf("native domain name or engine requires replacement")
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags, err := h.tags(ctx, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input, err := h.input(r.Properties)
	if err != nil {
		return result, err
	}
	input["DomainName"] = r.PhysicalID
	delete(input, "EngineVersion")
	if r.Properties["AccessPolicies"] == nil && r.Previous["AccessPolicies"] != nil {
		input["AccessPolicies"] = ""
	}
	desired, _ := cfnComputeObject(r.Properties["AdvancedOptions"])
	previous, _ := cfnComputeObject(r.Previous["AdvancedOptions"])
	options := map[string]any{}
	for k, v := range desired {
		options[k] = v
	}
	for k := range previous {
		if _, ok := desired[k]; !ok {
			switch k {
			case "indices.query.bool.max_clause_count":
				options[k] = "1024"
			case "rest.action.multi.allow_explicit_index":
				options[k] = "true"
			default:
				return result, fmt.Errorf("unsupported native option %s", k)
			}
		}
	}
	if len(options) > 0 {
		input["AdvancedOptions"] = options
	}
	if cfnComputeChanged(r.Previous, r.Properties, "AccessPolicies", "AdvancedOptions", "ClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions") {
		if err = cfnComputeRun(ctx, h.commands, "opensearch", "UpdateDomainConfig", input); err != nil {
			return result, err
		}
	}
	if err = h.updateTags(ctx, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	updated, err := h.Result(ctx, r)
	return cfnSearchAdmitted(r.PhysicalID, r.PhysicalID, updated, err)
}

// Delete is fenced inside the native transaction: a same-name domain recreated
// by another owner is absent to this incarnation and is never deleted.
func (h cfnOpenSearchDomain) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnSearchContext(ctx, r)
	name := cfnEngineName(r, "DomainName", 28)
	v, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if v.Deleted != nil && bool(*v.Deleted) {
		return nil
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "opensearch", "DeleteDomain", map[string]any{"DomainName": name}))
}
func (h cfnOpenSearchDomain) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnSearchContext(ctx, r)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"DomainName": cfnComputeValue(v.DomainName), "EngineVersion": cfnComputeValue(v.EngineVersion), "Arn": cfnComputeValue(v.ARN), "DomainArn": cfnComputeValue(v.ARN), "Id": cfnComputeValue(v.DomainId), "DomainEndpoint": cfnComputeValue(v.Endpoint), "ClusterConfig": v.ClusterConfig, "EBSOptions": v.EBSOptions, "EncryptionAtRestOptions": v.EncryptionAtRestOptions, "NodeToNodeEncryptionOptions": v.NodeToNodeEncryptionOptions, "DomainEndpointOptions": v.DomainEndpointOptions}
	options := map[string]string{}
	for k, v := range v.AdvancedOptions {
		options[string(k)] = string(v)
	}
	p["AdvancedOptions"] = options
	policy := cfnComputeValue(v.AccessPolicies)
	if policy != "" {
		var doc any
		if err = json.Unmarshal([]byte(policy), &doc); err != nil {
			return nil, err
		}
		p["AccessPolicies"] = doc
	}
	tags, err := h.tags(ctx, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnOpenSearchDomain) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out, err := cfnComputeCall[api.ListDomainNamesOutput](ctx, h.commands, "opensearch", "ListDomainNames", map[string]any{})
	if err != nil {
		return nil, err
	}
	result := []cloudformation.ResourceDescription{}
	for _, v := range out.DomainNames {
		r.PhysicalID = cfnComputeValue(v.DomainName)
		p, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		result = append(result, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
	}
	return result, nil
}
func (h cfnOpenSearchDomain) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnSearchContext(ctx, r), r.PhysicalID)
	if err != nil {
		return false, err
	}
	status := cfnComputeValue(v.DomainProcessingStatus)
	if status == "Isolated" {
		return false, fmt.Errorf("native domain failed")
	}
	return v.Processing != nil && !bool(*v.Processing) && v.Created != nil && bool(*v.Created), nil
}
func (h cfnOpenSearchDomain) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(cfnSearchContext(ctx, r), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnOpenSearchDomain) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(r.PhysicalID, p)
}

// AWS contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticsearch-domain.html
// The legacy frontend shares the OpenSearch domain owner and its private claim.
// Native legacy creation is rejected by that owner rather than aliased to an
// OpenSearch engine, so only existing-domain behavior is valid here.
type cfnElasticsearchDomain struct{ commands StepFunctionsCommands }

func (h cfnElasticsearchDomain) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "DomainName", "ElasticsearchVersion", "AccessPolicies", "AdvancedOptions", "ElasticsearchClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions", "Tags"); err != nil {
		return err
	}
	if p["AccessPolicies"] != nil {
		if _, err := cfnComputeDocument(p["AccessPolicies"]); err != nil {
			return err
		}
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnElasticsearchDomain) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DomainName", "ElasticsearchVersion", "ElasticsearchClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions"), h.Validate(b)
}
func (h cfnElasticsearchDomain) get(ctx context.Context, name string) (*legacyapi.ElasticsearchDomainStatus, error) {
	identifier := name
	if _, domain, ok := strings.Cut(name, "/"); ok {
		name = domain
	}
	out, err := cfnComputeCall[legacyapi.DescribeElasticsearchDomainOutput](ctx, h.commands, "es", "DescribeElasticsearchDomain", map[string]any{"DomainName": name})
	if err != nil {
		return nil, err
	}
	if out.DomainStatus == nil {
		return nil, fmt.Errorf("domain owner returned no status")
	}
	if identifier != name && cfnComputeValue(out.DomainStatus.DomainId) != identifier {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "native domain identifier not found", StatusCode: 404}
	}
	return out.DomainStatus, nil
}
func (h cfnElasticsearchDomain) tags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[legacyapi.ListTagsOutput](ctx, h.commands, "es", "ListTags", map[string]any{"ARN": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, t := range out.TagList {
		tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return tags, nil
}
func (h cfnElasticsearchDomain) updateTags(ctx context.Context, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	desired := cfnResourceTags(r)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, h.commands, "es", "RemoveTags", map[string]any{"ARN": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, h.commands, "es", "AddTags", map[string]any{"ARN": arn, "TagList": cfnComputeTagList(desired)})
}
func (h cfnElasticsearchDomain) input(p cloudformation.Properties) (map[string]any, error) {
	input := cfnComputeCopy(p, "DomainName", "ElasticsearchVersion", "AdvancedOptions", "ElasticsearchClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions")
	if p["AccessPolicies"] != nil {
		policy, err := cfnComputeDocument(p["AccessPolicies"])
		if err != nil {
			return nil, err
		}
		input["AccessPolicies"] = policy
	}
	return input, nil
}
func cfnElasticsearchID(r cloudformation.ResourceRequest, name string) string {
	return r.Scope.Account + "/" + name
}
func (h cfnElasticsearchDomain) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSearchCreateContext(ctx, r)
	name := cfnEngineName(r, "DomainName", 28)
	r.PhysicalID = name
	if _, err := h.get(ctx, name); err == nil {
		result, err := h.Result(ctx, r)
		return cfnSearchAdmitted(cfnElasticsearchID(r, name), name, result, err)
	} else if !cfnEngineMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input, err := h.input(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input["DomainName"] = name
	input["TagList"] = cfnComputeTagList(cfnResourceTags(r))
	if err = cfnComputeRun(ctx, h.commands, "es", "CreateElasticsearchDomain", input); err != nil {
		if _, readErr := h.get(ctx, name); readErr == nil {
			return cloudformation.ResourceResult{PhysicalID: cfnElasticsearchID(r, name), Ref: name}, err
		}
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.Result(ctx, r)
	return cfnSearchAdmitted(cfnElasticsearchID(r, name), name, result, err)
}
func (h cfnElasticsearchDomain) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnSearchCreateContext(ctx, r)
	name := cfnEngineName(r, "DomainName", 28)
	if _, domain, ok := strings.Cut(name, "/"); ok {
		name = domain
	}
	r.PhysicalID = name
	if _, err := h.get(ctx, name); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.Result(ctx, r)
	return cfnSearchAdmitted(cfnElasticsearchID(r, name), name, result, err)
}
func (h cfnElasticsearchDomain) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	ctx = cfnSearchContext(ctx, r)
	replacement, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replacement {
		return result, fmt.Errorf("native domain name or engine requires replacement")
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	result.Ref = cfnComputeValue(v.DomainName)
	tags, err := h.tags(ctx, cfnComputeValue(v.ARN))
	if err != nil {
		return result, err
	}
	input, err := h.input(r.Properties)
	if err != nil {
		return result, err
	}
	input["DomainName"] = cfnComputeValue(v.DomainName)
	delete(input, "ElasticsearchVersion")
	if r.Properties["AccessPolicies"] == nil && r.Previous["AccessPolicies"] != nil {
		input["AccessPolicies"] = ""
	}
	desired, _ := cfnComputeObject(r.Properties["AdvancedOptions"])
	previous, _ := cfnComputeObject(r.Previous["AdvancedOptions"])
	options := map[string]any{}
	for k, v := range desired {
		options[k] = v
	}
	for k := range previous {
		if _, ok := desired[k]; !ok {
			switch k {
			case "indices.query.bool.max_clause_count":
				options[k] = "1024"
			case "rest.action.multi.allow_explicit_index":
				options[k] = "true"
			default:
				return result, fmt.Errorf("unsupported native option %s", k)
			}
		}
	}
	if len(options) > 0 {
		input["AdvancedOptions"] = options
	}
	if cfnComputeChanged(r.Previous, r.Properties, "AccessPolicies", "AdvancedOptions", "ElasticsearchClusterConfig", "EBSOptions", "AdvancedSecurityOptions", "EncryptionAtRestOptions", "NodeToNodeEncryptionOptions", "DomainEndpointOptions") {
		if err = cfnComputeRun(ctx, h.commands, "es", "UpdateElasticsearchDomainConfig", input); err != nil {
			return result, err
		}
	}
	if err = h.updateTags(ctx, r, cfnComputeValue(v.ARN), tags); err != nil {
		return result, err
	}
	updated, err := h.Result(ctx, r)
	return cfnSearchAdmitted(result.PhysicalID, result.Ref, updated, err)
}
func (h cfnElasticsearchDomain) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnSearchContext(ctx, r)
	name := cfnEngineName(r, "DomainName", 28)
	v, err := h.get(ctx, name)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if v.Deleted != nil && bool(*v.Deleted) {
		return nil
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "es", "DeleteElasticsearchDomain", map[string]any{"DomainName": cfnComputeValue(v.DomainName)}))
}
func (h cfnElasticsearchDomain) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnSearchContext(ctx, r)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"DomainName": cfnComputeValue(v.DomainName), "ElasticsearchVersion": cfnComputeValue(v.ElasticsearchVersion), "Arn": cfnComputeValue(v.ARN), "DomainArn": cfnComputeValue(v.ARN), "Id": cfnComputeValue(v.DomainId), "DomainEndpoint": cfnComputeValue(v.Endpoint), "ElasticsearchClusterConfig": v.ElasticsearchClusterConfig, "EBSOptions": v.EBSOptions, "EncryptionAtRestOptions": v.EncryptionAtRestOptions, "NodeToNodeEncryptionOptions": v.NodeToNodeEncryptionOptions, "DomainEndpointOptions": v.DomainEndpointOptions}
	options := map[string]string{}
	for k, v := range v.AdvancedOptions {
		options[string(k)] = string(v)
	}
	p["AdvancedOptions"] = options
	policy := cfnComputeValue(v.AccessPolicies)
	if policy != "" {
		var doc any
		if err = json.Unmarshal([]byte(policy), &doc); err != nil {
			return nil, err
		}
		p["AccessPolicies"] = doc
	}
	tags, err := h.tags(ctx, cfnComputeValue(v.ARN))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnElasticsearchDomain) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	out, err := cfnComputeCall[legacyapi.ListDomainNamesOutput](ctx, h.commands, "es", "ListDomainNames", map[string]any{})
	if err != nil {
		return nil, err
	}
	result := []cloudformation.ResourceDescription{}
	for _, v := range out.DomainNames {
		r.PhysicalID = cfnComputeValue(v.DomainName)
		p, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeString(p, "Id"), Properties: p})
	}
	return result, nil
}
func (h cfnElasticsearchDomain) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(cfnSearchContext(ctx, r), r.PhysicalID)
	if err != nil {
		return false, err
	}
	status := cfnComputeValue(v.DomainProcessingStatus)
	if status == "Isolated" {
		return false, fmt.Errorf("native domain failed")
	}
	return v.Processing != nil && !bool(*v.Processing) && v.Created != nil && bool(*v.Created), nil
}
func (h cfnElasticsearchDomain) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(cfnSearchContext(ctx, r), r.PhysicalID)
	if cfnEngineMissing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnElasticsearchDomain) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := cfnEngineResult(cfnComputeString(p, "Id"), p)
	result.Ref = cfnComputeString(p, "DomainName")
	return result, err
}
