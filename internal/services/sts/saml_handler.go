package sts

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

var samlAccountID = regexp.MustCompile(`^[0-9]{12}$`)

func (s *Service) assumeRoleWithSAML(ctx context.Context) (output *stsapi.AssumeRoleWithSAMLOutput, failure *awswire.Error) {
	defer func() {
		if failure != nil {
			if err := s.appendAPICall(ctx, s.now(), "AssumeRoleWithSAML", nil, failure); err != nil {
				output, failure = nil, stsAuditFailure()
			}
		}
	}()
	input, ok := awsapi.Input[stsapi.AssumeRoleWithSAMLInput](ctx)
	if !ok {
		return nil, stsValidation("Missing AssumeRoleWithSAML input.")
	}
	roleARN, providerARN := value(input.RoleArn), value(input.PrincipalArn)
	role, err := arn.Parse(roleARN)
	if err != nil || role.Service != "iam" || role.Region != "" || !samlAccountID.MatchString(role.AccountID) || !strings.HasPrefix(role.Resource, "role/") || len(role.Resource) <= 5 {
		return nil, stsValidation("RoleArn must identify an IAM role.")
	}
	providerResource, err := arn.Parse(providerARN)
	if err != nil || providerResource.Service != "iam" || providerResource.Region != "" || !strings.HasPrefix(providerResource.Resource, "saml-provider/") || len(providerResource.Resource) <= 14 || providerResource.AccountID != role.AccountID || providerResource.Partition != role.Partition {
		return nil, stsValidation("PrincipalArn must identify a SAML provider in the role's account and partition.")
	}
	if partition := awsctx.FromContext(ctx).Partition; partition != "" && partition != role.Partition {
		return nil, stsValidation("The requested role is in a different AWS partition.")
	}
	name := role.Resource[strings.LastIndex(role.Resource, "/")+1:]
	if strings.HasPrefix(name, "AWSReservedSSO_") {
		return nil, stsValidation("AssumeRoleWithSAML cannot assume an IAM Identity Center managed role.")
	}
	duration := time.Hour
	if input.DurationSeconds != nil {
		duration = time.Duration(*input.DurationSeconds) * time.Second
	}
	if duration < 15*time.Minute || duration > 12*time.Hour {
		return nil, stsValidation("DurationSeconds must be between 900 and 43200 seconds.")
	}
	if s.samlProviders == nil {
		return nil, samlInvalid("No SAML provider source is configured.")
	}
	// The role ARN supplies the target storage scope for this unsigned API.
	// It is not an AWS caller identity or a policy principal-account claim.
	metadata := awsctx.FromContext(ctx)
	metadata.AccountID = role.AccountID
	metadata.Partition = role.Partition
	ctx = awsctx.WithMetadata(ctx, metadata)
	provider, err := s.samlProviders.SAMLProviderForFederation(ctx, providerARN)
	if err != nil {
		return nil, samlSourceError(err)
	}
	if provider.ARN != providerARN || provider.ID == "" || provider.Version == "" {
		return nil, samlInvalid("The requested SAML provider could not be verified.")
	}
	raw, err := samlBase64(value(input.SAMLAssertion))
	if err != nil {
		return nil, samlInvalid("The SAML response is not valid base64.")
	}
	now := s.now()
	claims, apiErr := verifySAMLResponse(raw, provider, roleARN, now)
	if apiErr != nil {
		return nil, apiErr
	}
	notAfter := claims.NotAfter
	if claims.SessionDuration > 0 {
		cap := now.Add(claims.SessionDuration)
		if notAfter.IsZero() || cap.Before(notAfter) {
			notAfter = cap
		}
	}
	ctx = context.WithValue(ctx, federationAuditKey{}, federationAudit{
		Identity:    samlIdentityAudit(claims.NameQualifier, claims.Subject),
		AssertionID: claims.AssertionID, SessionName: claims.SessionName, SourceIdentity: claims.SourceIdentity,
		Tags: claims.Tags, TransitiveTagKeys: claims.TransitiveTagKeys,
	})
	return issueFederatedRole(s, ctx, FederatedRoleRequest{
		Action: "sts:AssumeRoleWithSAML", ProviderARN: provider.ARN, ProviderID: provider.ID, ProviderVersion: provider.Version,
		RoleARN: roleARN, SessionName: claims.SessionName, SourceIdentity: claims.SourceIdentity, Subject: claims.Subject,
		Duration: duration, NotAfter: notAfter, Policy: value(input.Policy), PolicyARNs: input.PolicyArns, HasSessionPolicy: input.Policy != nil || len(input.PolicyArns) > 0,
		Tags: claims.Tags, TransitiveTagKeys: claims.TransitiveTagKeys, TrustContext: claims.TrustContext, SessionContext: claims.SessionContext,
		AuthenticationNotAfter: claims.AuthenticationNotAfter,
	}, func(issued FederatedRoleResult) *stsapi.AssumeRoleWithSAMLOutput {
		output := &stsapi.AssumeRoleWithSAMLOutput{
			Credentials:     credentialOutput(issued.Credential),
			AssumedRoleUser: &stsapi.AssumedRoleUser{Arn: ptr(stsapi.ArnType(issued.Credential.PrincipalARN)), AssumedRoleId: ptr(stsapi.AssumedRoleIdType(issued.Credential.PrincipalID))},
			Audience:        ptr(stsapi.Audience(claims.Audience)), Issuer: ptr(stsapi.Issuer(claims.Issuer)), Subject: ptr(stsapi.Subject(claims.Subject)), SubjectType: ptr(stsapi.SubjectType(claims.SubjectType)), NameQualifier: ptr(stsapi.NameQualifier(claims.NameQualifier)), PackedPolicySize: ptr(stsapi.NonNegativeIntegerType(issued.PackedPolicySize)),
		}
		if claims.SourceIdentity != "" {
			output.SourceIdentity = ptr(stsapi.SourceIdentityType(claims.SourceIdentity))
		}
		return output
	})
}

func samlSourceError(err error) *awswire.Error {
	if errors.Is(err, ErrFederationProviderNotFound) {
		return samlInvalid("The requested SAML provider does not exist.")
	}
	var apiErr *awswire.Error
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return &awswire.Error{Code: "IDPCommunicationError", Message: "Unable to retrieve the SAML provider's verification material.", StatusCode: 400}
}
