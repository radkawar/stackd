package sts

import (
	"context"

	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awscatalog"
	"stackd/internal/identity"
)

// IssueFederatedRole admits service-verified web-identity claims through current
// IAM trust, resource controls, session policy and the public STS transaction.
// Only trusted service adapters may call it; claims cannot be caller metadata.
func (s *Service) IssueFederatedRole(ctx context.Context, request FederatedRoleRequest) (identity.Credential, error) {
	if request.Action != "sts:AssumeRoleWithWebIdentity" {
		return identity.Credential{}, stsDenied("Service federation requires web identity.")
	}
	audience := ""
	if values := request.TrustContext[request.ProviderARN+":aud"]; len(values) != 0 {
		audience = values[0]
	}
	model, _ := awscatalog.LookupService("sts")
	operation, _ := model.Operation("AssumeRoleWithWebIdentity")
	ctx = awsapi.WithDecodedRequest(ctx, awsapi.DecodedRequest{Operation: operation, Input: &stsapi.AssumeRoleWithWebIdentityInput{
		RoleArn: new(stsapi.ArnType(request.RoleARN)), RoleSessionName: new(stsapi.RoleSessionNameType(request.SessionName)),
	}})
	ctx = context.WithValue(ctx, federationAuditKey{}, federationAudit{
		Identity: webIdentityAudit(request.ProviderARN, audience, request.Subject), SessionName: request.SessionName,
	})
	var credential identity.Credential
	_, rejected := issueFederatedRole(s, ctx, request, func(r FederatedRoleResult) *stsapi.AssumeRoleWithWebIdentityOutput {
		credential = r.Credential
		return &stsapi.AssumeRoleWithWebIdentityOutput{
			Credentials:     credentialOutput(r.Credential),
			AssumedRoleUser: &stsapi.AssumedRoleUser{Arn: new(stsapi.ArnType(r.Credential.PrincipalARN)), AssumedRoleId: new(stsapi.AssumedRoleIdType(r.Credential.PrincipalID))},
			Audience:        new(stsapi.Audience(audience)), Provider: new(stsapi.Issuer(request.ProviderARN)),
			SubjectFromWebIdentityToken: new(stsapi.WebIdentitySubjectType(request.Subject)), PackedPolicySize: new(stsapi.NonNegativeIntegerType(r.PackedPolicySize)),
		}
	})
	if rejected != nil {
		return identity.Credential{}, rejected
	}
	return credential, nil
}
