package iam

import iamapi "stackd/internal/awsapi/iam"

func resourceTagOutput(kind string, items []tag, p pagination) any {
	tags := wireTags(items)
	if tags == nil {
		tags = make(iamapi.TagListType, 0)
	}
	truncated := wirePointer(iamapi.BooleanType(p.IsTruncated))
	marker := wireMarker(p)
	switch kind {
	case "User":
		return &iamapi.ListUserTagsOutput{Tags: tags, IsTruncated: truncated, Marker: marker}
	case "Role":
		return &iamapi.ListRoleTagsOutput{Tags: tags, IsTruncated: truncated, Marker: marker}
	case "Policy":
		return &iamapi.ListPolicyTagsOutput{Tags: tags, IsTruncated: truncated, Marker: marker}
	case "MFADevice":
		return &iamapi.ListMFADeviceTagsOutput{Tags: tags, IsTruncated: truncated, Marker: marker}
	case "OIDC":
		return &iamapi.ListOpenIDConnectProviderTagsOutput{Tags: tags, IsTruncated: truncated, Marker: marker}
	case "SAML":
		return &iamapi.ListSAMLProviderTagsOutput{Tags: tags, IsTruncated: truncated, Marker: marker}
	default:
		return nil
	}
}
