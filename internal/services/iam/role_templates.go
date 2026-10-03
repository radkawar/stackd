package iam

import (
	"context"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/iam/roletemplates"
)

func lookupRoleTemplate(arn string, minor *iamapi.MinorVersionType) (*iamapi.RoleTemplateVersion, *awswire.Error) {
	version, err := roletemplates.Lookup(arn, minor)
	if err != nil {
		return nil, &awswire.Error{Code: "ServiceFailure", Message: "Unable to load role templates.", StatusCode: 500}
	}
	if version == nil {
		return nil, missing("role template", arn)
	}
	return version, nil
}

func getRoleTemplateVersion(ctx context.Context, _ *account, _ awsctx.Metadata) (any, *awswire.Error) {
	input, err := generatedIAMInput[iamapi.GetRoleTemplateVersionInput](ctx)
	if err != nil {
		return nil, err
	}
	version, err := lookupRoleTemplate(string(*input.TemplateArn), input.MinorVersion)
	if err != nil {
		return nil, err
	}
	version.AssumeRolePolicyDocumentTemplate = wirePointer(iamapi.PolicyDocumentType(encodedDocument(string(*version.AssumeRolePolicyDocumentTemplate))))
	for i := range version.InlinePolicyTemplates {
		policy := &version.InlinePolicyTemplates[i]
		policy.PolicyDocument = wirePointer(iamapi.PolicyDocumentType(encodedDocument(string(*policy.PolicyDocument))))
	}
	return &iamapi.GetRoleTemplateVersionOutput{RoleTemplateVersion: version}, nil
}
