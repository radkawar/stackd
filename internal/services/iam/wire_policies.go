package iam

import iamapi "stackd/internal/awsapi/iam"

func wirePolicy(p *policy, details bool) *iamapi.Policy {
	out := &iamapi.Policy{
		PolicyName: wirePointer(iamapi.PolicyNameType(p.PolicyName)), PolicyId: wirePointer(iamapi.IdType(p.PolicyId)),
		Arn: wirePointer(iamapi.ArnType(p.Arn)), Path: wirePointer(iamapi.PolicyPathType(p.Path)),
		DefaultVersionId:              wirePointer(iamapi.PolicyVersionIdType(p.DefaultVersionId)),
		AttachmentCount:               wirePointer(iamapi.AttachmentCountType(p.AttachmentCount)),
		PermissionsBoundaryUsageCount: wirePointer(iamapi.AttachmentCountType(p.PermissionsBoundaryUsageCount)),
		IsAttachable:                  wirePointer(iamapi.BooleanType(p.IsAttachable)),
		CreateDate:                    wirePointer(p.CreateDate), UpdateDate: wirePointer(p.UpdateDate),
	}
	if details {
		out.Tags = wireTags(p.Tags)
		if p.Description != "" {
			out.Description = wirePointer(iamapi.PolicyDescriptionType(p.Description))
		}
	}
	return out
}

func wirePolicyVersion(version *policyVersion, document bool) *iamapi.PolicyVersion {
	out := &iamapi.PolicyVersion{
		VersionId:        wirePointer(iamapi.PolicyVersionIdType(version.VersionId)),
		IsDefaultVersion: wirePointer(iamapi.BooleanType(version.IsDefaultVersion)),
		CreateDate:       wirePointer(version.CreateDate),
	}
	if document {
		out.Document = wirePointer(iamapi.PolicyDocumentType(encodedDocument(version.Document)))
	}
	return out
}
