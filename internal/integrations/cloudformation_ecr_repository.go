package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/ecr"
	"stackd/internal/services/cloudformation"
)

type cfnECRRepository struct{ commands StepFunctionsCommands }

func (h cfnECRRepository) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "RepositoryName", "ImageTagMutability", "ImageScanningConfiguration", "EncryptionConfiguration", "LifecyclePolicy", "RepositoryPolicyText", "EmptyOnDelete", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "RepositoryName", "ImageTagMutability"); err != nil {
		return err
	}
	if raw, ok := p["EmptyOnDelete"]; ok {
		if _, ok := raw.(bool); !ok {
			return fmt.Errorf("EmptyOnDelete must be a boolean")
		}
	}
	for _, key := range []string{"ImageScanningConfiguration", "EncryptionConfiguration", "LifecyclePolicy"} {
		if p[key] == nil {
			continue
		}
		v, ok := cfnComputeObject(p[key])
		if !ok {
			return fmt.Errorf("%s must be an object", key)
		}
		var fields []string
		switch key {
		case "ImageScanningConfiguration":
			fields = []string{"ScanOnPush"}
		case "EncryptionConfiguration":
			fields = []string{"EncryptionType", "KmsKey"}
		case "LifecyclePolicy":
			fields = []string{"LifecyclePolicyText", "RegistryId"}
		}
		if err := cfnComputeProperties(v, fields...); err != nil {
			return err
		}
	}
	if p["RepositoryPolicyText"] != nil {
		if _, err := cfnComputeDocument(p["RepositoryPolicyText"]); err != nil {
			return err
		}
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnECRRepository) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "RepositoryName", "EncryptionConfiguration"), h.Validate(b)
}
func (h cfnECRRepository) get(ctx context.Context, name string) (*api.Repository, error) {
	out, err := cfnComputeCall[api.DescribeRepositoriesOutput](ctx, h.commands, "ecr", "DescribeRepositories", map[string]any{"repositoryNames": []string{name}})
	if err != nil {
		return nil, err
	}
	if len(out.Repositories) != 1 {
		return nil, fmt.Errorf("ECR returned no repository for %s", name)
	}
	return &out.Repositories[0], nil
}
func (h cfnECRRepository) tags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, h.commands, "ecr", "ListTagsForResource", map[string]any{"resourceArn": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, tag := range out.Tags {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return tags, nil
}
func cfnECRTags(tags map[string]string) []map[string]string {
	out := cfnComputeTagList(tags)
	for _, tag := range out {
		tag["key"], tag["value"] = tag["Key"], tag["Value"]
		delete(tag, "Key")
		delete(tag, "Value")
	}
	return out
}
func cfnECRConfiguration(raw any) map[string]any {
	object, _ := cfnComputeObject(raw)
	if object == nil {
		return nil
	}
	result := make(map[string]any, len(object))
	for key, value := range object {
		result[strings.ToLower(key[:1])+key[1:]] = value
	}
	return result
}
func cfnECRResult(repo *api.Repository) cloudformation.ResourceResult {
	name := cfnComputeValue(repo.RepositoryName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": cfnComputeValue(repo.RepositoryArn), "RepositoryUri": cfnComputeValue(repo.RepositoryUri)}}
}
func (h cfnECRRepository) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "RepositoryName", 256)
	if r.Properties["RepositoryName"] == nil && r.PhysicalID == "" {
		name = strings.ToLower(name)
	}
	repo, err := h.get(ctx, name)
	if err == nil {
		tags, err := h.tags(ctx, cfnComputeValue(repo.RepositoryArn))
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if err := cfnComputeOwnership(r, tags); err != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
	} else {
		if !cfnMessagingMissing(err, "RepositoryNotFoundException") {
			return cloudformation.ResourceResult{}, err
		}
		input := map[string]any{"repositoryName": name, "tags": cfnECRTags(cfnComputeOwnedTags(r))}
		if p := r.Properties["ImageTagMutability"]; p != nil {
			input["imageTagMutability"] = p
		}
		for _, key := range []string{"ImageScanningConfiguration", "EncryptionConfiguration"} {
			if p := r.Properties[key]; p != nil {
				input[strings.ToLower(key[:1])+key[1:]] = cfnECRConfiguration(p)
			}
		}
		out, err := cfnComputeCall[api.CreateRepositoryOutput](ctx, h.commands, "ecr", "CreateRepository", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		repo = out.Repository
	}
	result := cfnECRResult(repo)
	return result, h.policies(ctx, r, name)
}
func (h cfnECRRepository) policies(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	if raw := r.Properties["RepositoryPolicyText"]; raw != nil {
		document, err := cfnComputeDocument(raw)
		if err != nil {
			return err
		}
		if err := cfnComputeRun(ctx, h.commands, "ecr", "SetRepositoryPolicy", map[string]any{"repositoryName": name, "policyText": document}); err != nil {
			return err
		}
	} else if r.Previous["RepositoryPolicyText"] != nil {
		err := cfnComputeRun(ctx, h.commands, "ecr", "DeleteRepositoryPolicy", map[string]any{"repositoryName": name})
		if err != nil && !cfnMessagingMissing(err, "RepositoryPolicyNotFoundException") {
			return err
		}
	}
	if raw := r.Properties["LifecyclePolicy"]; raw != nil {
		p, _ := cfnComputeObject(raw)
		input := map[string]any{"repositoryName": name, "lifecyclePolicyText": p["LifecyclePolicyText"]}
		if p["RegistryId"] != nil {
			input["registryId"] = p["RegistryId"]
		}
		return cfnComputeRun(ctx, h.commands, "ecr", "PutLifecyclePolicy", input)
	} else if r.Previous["LifecyclePolicy"] != nil {
		err := cfnComputeRun(ctx, h.commands, "ecr", "DeleteLifecyclePolicy", map[string]any{"repositoryName": name})
		if !cfnMessagingMissing(err, "LifecyclePolicyNotFoundException") {
			return err
		}
	}
	return nil
}
func (h cfnECRRepository) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	repo, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnECRResult(repo)
	tags, err := h.tags(ctx, cfnComputeValue(repo.RepositoryArn))
	if err != nil {
		return result, err
	}
	if !r.CloudControl {
		if err := cfnComputeOwnership(r, tags); err != nil {
			return result, err
		}
	}
	if err := cfnComputeRun(ctx, h.commands, "ecr", "PutImageTagMutability", map[string]any{"repositoryName": r.PhysicalID, "imageTagMutability": cfnComputeDefault(r.Properties, "ImageTagMutability", "MUTABLE")}); err != nil {
		return result, err
	}
	scan := cfnECRConfiguration(r.Properties["ImageScanningConfiguration"])
	if scan == nil {
		scan = map[string]any{"scanOnPush": false}
	}
	if err := cfnComputeRun(ctx, h.commands, "ecr", "PutImageScanningConfiguration", map[string]any{"repositoryName": r.PhysicalID, "imageScanningConfiguration": scan}); err != nil {
		return result, err
	}
	if err := h.policies(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	desired := cfnResourceMutationTags(r, tags, cfnComputeOwnedTags(r))
	if removed := cfnComputeRemovedTags(tags, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, h.commands, "ecr", "UntagResource", map[string]any{"resourceArn": cfnComputeValue(repo.RepositoryArn), "tagKeys": removed}); err != nil {
			return result, err
		}
	}
	if len(desired) == 0 {
		return result, nil
	}
	return result, cfnComputeRun(ctx, h.commands, "ecr", "TagResource", map[string]any{"resourceArn": cfnComputeValue(repo.RepositoryArn), "tags": cfnECRTags(desired)})
}
func (h cfnECRRepository) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "RepositoryName", 256)
	repo, err := h.get(ctx, name)
	if cfnMessagingMissing(err, "RepositoryNotFoundException") {
		return nil
	}
	if err != nil {
		return err
	}
	if !r.CloudControl {
		tags, err := h.tags(ctx, cfnComputeValue(repo.RepositoryArn))
		if err != nil {
			return err
		}
		if err := cfnComputeOwnership(r, tags); err != nil {
			return err
		}
	}
	force, _ := r.Properties["EmptyOnDelete"].(bool)
	err = cfnComputeRun(ctx, h.commands, "ecr", "DeleteRepository", map[string]any{"repositoryName": name, "force": force})
	if cfnMessagingMissing(err, "RepositoryNotFoundException") {
		return nil
	}
	return err
}
func (h cfnECRRepository) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	repo, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"RepositoryName": r.PhysicalID, "Arn": cfnComputeValue(repo.RepositoryArn), "RepositoryUri": cfnComputeValue(repo.RepositoryUri), "ImageTagMutability": cfnComputeValue(repo.ImageTagMutability)}
	if repo.EncryptionConfiguration != nil {
		config := map[string]any{"EncryptionType": cfnComputeValue(repo.EncryptionConfiguration.EncryptionType)}
		if repo.EncryptionConfiguration.KmsKey != nil {
			config["KmsKey"] = cfnComputeValue(repo.EncryptionConfiguration.KmsKey)
		}
		p["EncryptionConfiguration"] = config
	}
	if repo.ImageScanningConfiguration != nil && repo.ImageScanningConfiguration.ScanOnPush != nil {
		p["ImageScanningConfiguration"] = map[string]any{"ScanOnPush": bool(*repo.ImageScanningConfiguration.ScanOnPush)}
	}
	policy, err := cfnComputeCall[api.GetRepositoryPolicyOutput](ctx, h.commands, "ecr", "GetRepositoryPolicy", map[string]any{"repositoryName": r.PhysicalID})
	if err != nil && !cfnMessagingMissing(err, "RepositoryPolicyNotFoundException") {
		return nil, err
	}
	if err == nil {
		var doc any
		if err := json.Unmarshal([]byte(cfnComputeValue(policy.PolicyText)), &doc); err != nil {
			return nil, err
		}
		p["RepositoryPolicyText"] = doc
	}
	lifecycle, err := cfnComputeCall[api.GetLifecyclePolicyOutput](ctx, h.commands, "ecr", "GetLifecyclePolicy", map[string]any{"repositoryName": r.PhysicalID})
	if err != nil && !cfnMessagingMissing(err, "LifecyclePolicyNotFoundException") {
		return nil, err
	}
	if err == nil {
		p["LifecyclePolicy"] = map[string]any{"LifecyclePolicyText": cfnComputeValue(lifecycle.LifecyclePolicyText)}
	}
	tags, err := h.tags(ctx, cfnComputeValue(repo.RepositoryArn))
	if err != nil {
		return nil, err
	}
	for k := range tags {
		if strings.HasPrefix(k, cfnComputeTagPrefix) || strings.HasPrefix(k, "aws:") {
			delete(tags, k)
		}
	}
	p["Tags"] = cfnComputeTagList(tags)
	return p, nil
}
func (h cfnECRRepository) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeRepositoriesOutput](ctx, h.commands, "ecr", "DescribeRepositories", in)
		if err != nil {
			return nil, err
		}
		for _, repo := range out.Repositories {
			name := cfnComputeValue(repo.RepositoryName)
			result = append(result, cloudformation.ResourceDescription{Identifier: name, Properties: cloudformation.Properties{"RepositoryName": name}})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		in["nextToken"] = *out.NextToken
	}
}
