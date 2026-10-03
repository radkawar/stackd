package iam

import (
	"context"
	"strings"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
)

// The generated action catalogue determines resource types. Resolving names to
// current records belongs to IAM: request names omit stored paths, and access
// keys must be resolved to their owning identity before authorizing their use.
func (s *Service) authorizationResource(ctx context.Context, a *account, m awsctx.Metadata) (string, []tag, string, *awswire.Error) {
	decoded, _ := awsapi.FromContext(ctx)
	action, input := string(decoded.Operation.Name), decoded.Input
	if action == "GenerateServiceLastAccessedDetails" || action == "ListPoliciesGrantingServiceAccess" {
		arn := inputString(input.(interface{ InputARN() *iamapi.ArnType }).InputARN())
		if strings.Contains(arn, ":policy/") {
			return arn, nil, "", nil
		}
		identity, apiErr := lastAccessIdentity(a, m, arn)
		if apiErr != nil {
			return "", nil, "", apiErr
		}
		return identity.arn, nil, "", nil
	}
	if resource, handled := s.serviceLinkedAuthorizationResource(ctx, a, m); handled {
		return resource, nil, "", nil
	}
	if resource, tags, handled := federationAuthorizationResource(ctx, a, m); handled {
		return resource, tags, "", nil
	}
	if resource, handled := serviceCredentialAuthorizationResource(ctx, m); handled {
		return resource, nil, "", nil
	}
	metadata, err := catalog.Load()
	if err != nil {
		return "", nil, "", authorizationMetadataFailure()
	}
	definition, ok := metadata.LookupAction("iam:" + action)
	if !ok || definition.Ambiguous {
		return "", nil, "", authorizationMetadataFailure()
	}
	sourceKind, sourceName := "", ""
	if in, ok := input.(interface{ PolicySourceARN() *iamapi.ArnType }); ok {
		sourceARN := inputString(in.PolicySourceARN())
		var sourceErr *awswire.Error
		sourceKind, sourceName, sourceErr = contextKeySourceARN(sourceARN)
		if sourceErr != nil {
			return "", nil, "", sourceErr
		}
		parts := strings.SplitN(sourceARN, ":", 6)
		if parts[1] != m.Partition || parts[4] != m.AccountID {
			if action == "SimulatePrincipalPolicy" {
				return "", nil, "", invalidInput("PolicySourceArn must identify an IAM user, group, or role in this account.")
			}
			return sourceARN, nil, "", nil
		}
	}
	kind := ""
	for _, resource := range definition.Resources {
		if sourceKind != "" && resource != sourceKind {
			continue
		}
		if resource == "" {
			continue
		}
		if kind != "" && kind != resource {
			if (kind == "mfa" || kind == "sms-mfa") && (resource == "mfa" || resource == "sms-mfa") {
				kind = "mfa"
				if strings.Contains(authorizationResourceName(input, "mfa"), ":sms-mfa/") {
					kind = "sms-mfa"
				}
				continue
			}
			return "", nil, "", authorizationMetadataFailure()
		}
		kind = resource
	}
	if kind == "" {
		return "*", nil, "", nil
	}
	if arn, creating := creationAuthorizationResource(input, m, kind); creating {
		return arn, nil, "", nil
	}
	if in, ok := input.(*iamapi.GetAccessKeyLastUsedInput); ok {
		key, _, err := s.credentialStore(ctx).AccessKeyLastUsed(m.AccountID, inputString(in.AccessKeyId))
		if err != nil {
			return "*", nil, "", nil
		}
		for _, user := range a.users {
			if user.UserId == key.Principal.ID {
				return user.Arn, user.Tags, boundaryARN(user.PermissionsBoundary), nil
			}
		}
		return key.Principal.ARN, nil, "", nil
	}
	name := authorizationResourceName(input, kind)
	if sourceKind != "" {
		name = sourceName
	}
	switch kind {
	case "role-template":
		if in, ok := input.(interface{ TemplateARN() *iamapi.ArnType }); ok {
			return inputString(in.TemplateARN()), nil, "", nil
		}
		return "", nil, "", authorizationMetadataFailure()
	case "access-report":
		if in, ok := input.(*iamapi.GenerateOrganizationsAccessReportInput); ok {
			return resourceARN(m, kind, "/", inputString(in.EntityPath)), nil, "", nil
		}
		return "", nil, "", authorizationMetadataFailure()
	case "user":
		if name == "" {
			name = m.UserName
		}
		if u := a.users[strings.ToLower(name)]; u != nil {
			return u.Arn, u.Tags, boundaryARN(u.PermissionsBoundary), nil
		}
		if name == "" {
			return "arn:" + m.Partition + ":iam::" + m.AccountID + ":root", nil, "", nil
		}
	case "group":
		if g := a.groups[strings.ToLower(name)]; g != nil {
			return g.Arn, nil, "", nil
		}
	case "role":
		if r := a.roles[strings.ToLower(name)]; r != nil {
			return r.Arn, r.Tags, boundaryARN(r.PermissionsBoundary), nil
		}
	case "policy":
		arn := ""
		if in, ok := input.(interface{ PolicyARN() *iamapi.ArnType }); ok {
			arn = inputString(in.PolicyARN())
		}
		if p := a.policies[arn]; p != nil {
			return p.Arn, p.Tags, "", nil
		}
		if arn != "" {
			return arn, nil, "", nil
		}
	case "server-certificate":
		if r := a.serverCertificates[strings.ToLower(name)]; r != nil {
			return r.ARN, r.Tags, "", nil
		}
	case "instance-profile":
		if p := a.instanceProfiles[strings.ToLower(name)]; p != nil {
			return p.Arn, p.Tags, "", nil
		}
	case "mfa", "sms-mfa":
		serial := name
		if d := a.mfaDevices[serial]; d != nil {
			return serial, d.Tags, "", nil
		}
		if serial != "" {
			return serial, nil, "", nil
		}
		return "*", nil, "", nil
	default:
		return "", nil, "", authorizationMetadataFailure()
	}
	return resourceARN(m, kind, "/", name), nil, "", nil
}

func authorizationMetadataFailure() *awswire.Error {
	return &awswire.Error{Code: "ServiceFailure", Message: "IAM authorization resource metadata could not be resolved.", StatusCode: 500}
}
