package iam

import (
	"context"
	"slices"
	"strings"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// The generated decoder owns tag count, length and character constraints.
// These resource rules run after authorization and before any tag is written.
func inputTags(input iamapi.TagListType, kind string) ([]tag, *awswire.Error) {
	tags := make([]tag, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, entry := range input {
		key, value := inputString(entry.Key), inputString(entry.Value)
		// AWS accepts aws: in values; only keys reserve this prefix.
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, invalidInput("Tag keys cannot begin with the reserved aws: prefix.")
		}
		if _, ok := seen[tagKey(kind, key)]; ok {
			return nil, invalidInput("Duplicate tag keys are not allowed.")
		}
		seen[tagKey(kind, key)] = struct{}{}
		tags = append(tags, tag{key, value})
	}
	slices.SortFunc(tags, func(a, b tag) int { return strings.Compare(a.Key, b.Key) })
	return tags, nil
}

func resourceTags(a *account, kind, name string) (*[]tag, *awswire.Error) {
	switch kind {
	case "MFADevice":
		device, err := findMFADevice(a, name)
		if err != nil {
			return nil, err
		}
		return &device.Tags, nil
	case "User":
		u, err := findUser(a, name)
		if err != nil {
			return nil, err
		}
		return &u.Tags, nil
	case "Role":
		r, err := findRole(a, name)
		if err != nil {
			return nil, err
		}
		return &r.Tags, nil
	case "Policy":
		p, err := findPolicyARN(a, name)
		if err != nil {
			return nil, err
		}
		return &p.Tags, nil
	case "OIDC":
		p, err := findOIDCProvider(a, name)
		if err != nil {
			return nil, err
		}
		return &p.Tags, nil
	case "SAML":
		p, err := findSAMLProvider(a, name)
		if err != nil {
			return nil, err
		}
		return &p.Tags, nil
	default:
		return nil, requestBindingFailure()
	}
}

func tagResource(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	decoded, _ := awsapi.FromContext(ctx)
	var kind, name string
	var input iamapi.TagListType
	switch in := decoded.Input.(type) {
	case *iamapi.TagUserInput:
		kind, name, input = "User", inputString(in.UserName), in.Tags
	case *iamapi.TagRoleInput:
		kind, name, input = "Role", inputString(in.RoleName), in.Tags
	case *iamapi.TagPolicyInput:
		kind, name, input = "Policy", inputString(in.PolicyArn), in.Tags
	case *iamapi.TagMFADeviceInput:
		kind, name, input = "MFADevice", inputString(in.SerialNumber), in.Tags
	case *iamapi.TagOpenIDConnectProviderInput:
		kind, name, input = "OIDC", inputString(in.OpenIDConnectProviderArn), in.Tags
	case *iamapi.TagSAMLProviderInput:
		kind, name, input = "SAML", inputString(in.SAMLProviderArn), in.Tags
	default:
		return nil, requestBindingFailure()
	}
	if kind == "Policy" && isAWSManagedPolicyARN(name) {
		return nil, invalidInput("Tags not supported for policies in this domain")
	}
	target, err := resourceTags(a, kind, name)
	if err != nil {
		return nil, err
	}
	tags, err := inputTags(input, kind)
	if err != nil {
		return nil, err
	}
	if len(tags) == 0 {
		return nil, invalidInput("At least one tag is required.")
	}
	if err := mergeTags(target, tags, kind); err != nil {
		return nil, err
	}
	return &iamapi.Unit{}, nil
}

func untagResource(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	decoded, _ := awsapi.FromContext(ctx)
	var kind, name string
	var keys iamapi.TagKeyListType
	switch in := decoded.Input.(type) {
	case *iamapi.UntagUserInput:
		kind, name, keys = "User", inputString(in.UserName), in.TagKeys
	case *iamapi.UntagRoleInput:
		kind, name, keys = "Role", inputString(in.RoleName), in.TagKeys
	case *iamapi.UntagPolicyInput:
		kind, name, keys = "Policy", inputString(in.PolicyArn), in.TagKeys
	case *iamapi.UntagMFADeviceInput:
		kind, name, keys = "MFADevice", inputString(in.SerialNumber), in.TagKeys
	case *iamapi.UntagOpenIDConnectProviderInput:
		kind, name, keys = "OIDC", inputString(in.OpenIDConnectProviderArn), in.TagKeys
	case *iamapi.UntagSAMLProviderInput:
		kind, name, keys = "SAML", inputString(in.SAMLProviderArn), in.TagKeys
	default:
		return nil, requestBindingFailure()
	}
	if kind == "Policy" && isAWSManagedPolicyARN(name) {
		return nil, invalidInput("Tags not supported for policies in this domain")
	}
	target, err := resourceTags(a, kind, name)
	if err != nil {
		return nil, err
	}
	if (kind == "OIDC" || kind == "SAML") && len(keys) == 0 {
		return nil, invalidInput("At least one tag key is required.")
	}
	removeTags(target, keys, kind)
	return &iamapi.Unit{}, nil
}

func listResourceTags(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	decoded, _ := awsapi.FromContext(ctx)
	var kind, name string
	switch in := decoded.Input.(type) {
	case *iamapi.ListUserTagsInput:
		kind, name = "User", inputString(in.UserName)
	case *iamapi.ListRoleTagsInput:
		kind, name = "Role", inputString(in.RoleName)
	case *iamapi.ListPolicyTagsInput:
		kind, name = "Policy", inputString(in.PolicyArn)
	case *iamapi.ListMFADeviceTagsInput:
		kind, name = "MFADevice", inputString(in.SerialNumber)
	case *iamapi.ListOpenIDConnectProviderTagsInput:
		kind, name = "OIDC", inputString(in.OpenIDConnectProviderArn)
	case *iamapi.ListSAMLProviderTagsInput:
		kind, name = "SAML", inputString(in.SAMLProviderArn)
	default:
		return nil, requestBindingFailure()
	}
	target, err := resourceTags(a, kind, name)
	if err != nil {
		return nil, err
	}
	items, p, err := page(ctx, slices.Clone(*target), func(t tag) string { return t.Key }, m, decoded.Input)
	return resourceTagOutput(kind, items, p), err
}

// mergeTags replaces matching keys only after the combined set passes the quota.
// User and role keys match without case; other IAM resources retain both cases.
func mergeTags(target *[]tag, incoming []tag, kind string) *awswire.Error {
	merged := make(map[string]tag, len(*target)+len(incoming))
	for _, t := range *target {
		merged[tagKey(kind, t.Key)] = t
	}
	for _, t := range incoming {
		merged[tagKey(kind, t.Key)] = t
	}
	if len(merged) > 50 {
		return limit("A resource may have at most 50 tags.")
	}
	result := make([]tag, 0, len(merged))
	for _, t := range merged {
		result = append(result, t)
	}
	slices.SortFunc(result, func(a, b tag) int { return strings.Compare(a.Key, b.Key) })
	*target = result
	return nil
}

func removeTags(target *[]tag, input iamapi.TagKeyListType, kind string) {
	keys := make(map[string]bool, len(input))
	for _, key := range input {
		keys[tagKey(kind, string(key))] = true
	}
	*target = slices.DeleteFunc(*target, func(t tag) bool { return keys[tagKey(kind, t.Key)] })
}

func tagKey(kind, key string) string {
	if kind == "User" || kind == "Role" {
		return strings.ToLower(key)
	}
	return key
}
