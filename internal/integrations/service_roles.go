package integrations

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"stackd/internal/authorization"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

// ServiceRoleAuthority joins current role resolution and credential issuance in
// the same IAM transaction used by gateway authentication.
type ServiceRoleAuthority interface {
	WithSession(context.Context, func(context.Context, identity.Repository, time.Time) error) error
	RoleForAssumption(context.Context, string) (iam.RoleSnapshot, error)
}

// STSRoleEvents records service assumptions through STS's ordinary projection.
type STSRoleEvents interface {
	RecordAssumeRole(context.Context, time.Time, *stsapi.AssumeRoleInput, *stsapi.AssumeRoleOutput) error
}

// ServiceRoles owns trust-authorized sessions for actual service execution.
// Consumers own their public PassRole and service-specific error contracts.
type ServiceRoles struct {
	IAM         ServiceRoleAuthority
	Credentials *identity.Store
	Authorizer  authorization.Authorizer
	STS         STSRoleEvents
}

func (a ServiceRoles) assume(ctx context.Context, source awsctx.ServicePrincipal, roleARN string, session identity.RoleSessionSpec, externalID string) (identity.Credential, *awswire.Error) {
	return a.assumeResolved(ctx, source, session, externalID, func(context.Context) (string, error) { return roleARN, nil })
}

// assumeResolved resolves a service-owned role relationship inside the same IAM
// transaction as current trust and credential issuance. Pre-issuance relationship
// and trust rejections are outcomes, not failed writes: a caller may need to
// commit pending delivery state. Issuance/audit failures still abort all writes.
func (a ServiceRoles) assumeResolved(ctx context.Context, source awsctx.ServicePrincipal, session identity.RoleSessionSpec, externalID string, resolveRole func(context.Context) (string, error)) (identity.Credential, *awswire.Error) {
	if session.Duration == 0 {
		session.Duration = time.Hour
	}
	return a.assumeResolvedSession(ctx, source, externalID, func(ctx context.Context) (string, identity.RoleSessionSpec, error) {
		arn, err := resolveRole(ctx)
		return arn, session, err
	})
}

// assumeResolvedSession also resolves service-owned issuance properties, such as
// Identity Center's provisioned duration, under the current IAM transaction.
func (a ServiceRoles) assumeResolvedSession(ctx context.Context, source awsctx.ServicePrincipal, externalID string, resolveSession func(context.Context) (string, identity.RoleSessionSpec, error)) (identity.Credential, *awswire.Error) {
	ctx = awsctx.WithServicePrincipal(ctx, source)
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	metadata.SourceIP, metadata.UserAgent = source.Name, source.Name
	ctx = awsctx.WithMetadata(ctx, metadata)
	if a.IAM == nil || a.Credentials == nil || a.Authorizer == nil {
		return identity.Credential{}, serviceRoleFailure(errors.New("service role authority is not configured"))
	}
	var result identity.Credential
	var rejected *awswire.Error
	err := a.IAM.WithSession(ctx, func(ctx context.Context, repository identity.Repository, now time.Time) error {
		roleARN, session, err := resolveSession(ctx)
		if err != nil {
			if errors.As(err, &rejected) && rejected.StatusCode >= 400 && rejected.StatusCode < 500 {
				return nil
			}
			return err
		}
		role, err := a.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			rejected = &awswire.Error{Code: "AccessDenied", Message: "User: " + source.Name + " is not authorized to perform: sts:AssumeRole on resource: " + roleARN + ".", StatusCode: 403}
			return nil
		}
		if session.Role.ID != "" && session.Role.ID != role.ID {
			rejected = &awswire.Error{Code: "AccessDenied", Message: "The service role relationship no longer identifies the current IAM role.", StatusCode: 403}
			return nil
		}
		if rejected = a.trust(ctx, role, session, now, externalID); rejected != nil {
			if rejected.StatusCode >= 500 {
				return rejected
			}
			return nil
		}
		// Credential ownership follows the resolved IAM role, not the account
		// owning the triggering resource used by the trust context.
		_, accountAndResource, _ := strings.Cut(role.ARN, "::")
		roleAccount, _, _ := strings.Cut(accountAndResource, ":")
		session.Role = identity.Principal{AccountID: roleAccount, ARN: role.ARN, ID: role.ID}
		credential, err := a.Credentials.WithRepositoryAt(repository, now).IssueServiceRoleSession(ctx, session)
		if err != nil {
			return err
		}
		result = credential
		if a.STS != nil {
			roleInput, nameInput, duration := stsapi.ArnType(roleARN), stsapi.RoleSessionNameType(session.SessionName), stsapi.RoleDurationSecondsType(session.Duration/time.Second)
			input := &stsapi.AssumeRoleInput{RoleArn: &roleInput, RoleSessionName: &nameInput, DurationSeconds: &duration}
			if externalID != "" {
				input.ExternalId = new(stsapi.ExternalIdType(externalID))
			}
			for _, key := range slices.Sorted(maps.Keys(session.Tags)) {
				input.Tags = append(input.Tags, stsapi.Tag{Key: new(stsapi.TagKeyType(key)), Value: new(stsapi.TagValueType(session.Tags[key]))})
			}
			for _, key := range session.TransitiveTagKeys {
				input.TransitiveTagKeys = append(input.TransitiveTagKeys, stsapi.TagKeyType(key))
			}
			if len(session.Policies) == 1 {
				input.Policy = new(stsapi.UnrestrictedSessionPolicyDocumentType(session.Policies[0]))
			}
			for _, arn := range session.PolicyARNs {
				input.PolicyArns = append(input.PolicyArns, stsapi.PolicyDescriptorType{Arn: new(stsapi.ArnType(arn))})
			}
			return a.STS.RecordAssumeRole(ctx, now, input, serviceAssumeRoleOutput(credential))
		}
		return nil
	})
	if err != nil {
		return identity.Credential{}, serviceRoleFailure(err)
	}
	if rejected != nil {
		return identity.Credential{}, rejected
	}
	return result, nil
}

func (a ServiceRoles) trust(ctx context.Context, role iam.RoleSnapshot, session identity.RoleSessionSpec, now time.Time, externalID string) *awswire.Error {
	values := map[string][]string{"sts:rolesessionname": {session.SessionName}}
	if len(session.Tags) != 0 {
		values["aws:tagkeys"] = slices.Sorted(maps.Keys(session.Tags))
		for _, key := range values["aws:tagkeys"] {
			values["aws:requesttag/"+strings.ToLower(key)] = []string{session.Tags[key]}
		}
	}
	if len(session.TransitiveTagKeys) != 0 {
		values["sts:transitivetagkeys"] = session.TransitiveTagKeys
	}
	if externalID != "" {
		values["sts:externalid"] = []string{externalID}
	}
	for key, value := range role.Tags {
		values["aws:resourcetag/"+strings.ToLower(key)] = []string{value}
	}
	request := authorization.Request{
		Action: "sts:AssumeRole", ResourceARN: role.ARN,
		ResourcePolicies:      []authorization.BoundPolicy{{Document: role.TrustPolicy, PrincipalIDs: role.TrustPrincipalIDs, TrustPolicy: true}},
		ResourceControlExempt: role.ServiceLinkedRole, Context: values, EvaluationTime: &now,
	}
	if rejected := a.Authorizer.Authorize(ctx, request); rejected != nil {
		return rejected
	}
	if len(session.Tags) != 0 {
		request.Action = "sts:TagSession"
		return a.Authorizer.Authorize(ctx, request)
	}
	return nil
}

func serviceAssumeRoleOutput(credential identity.Credential) *stsapi.AssumeRoleOutput {
	key, secret, token := stsapi.AccessKeyIdType(credential.AccessKeyID), stsapi.AccessKeySecretType(credential.SecretAccessKey), stsapi.TokenType(credential.SessionToken)
	roleARN, roleID := stsapi.ArnType(credential.PrincipalARN), stsapi.AssumedRoleIdType(credential.PrincipalID)
	return &stsapi.AssumeRoleOutput{
		Credentials:     &stsapi.Credentials{AccessKeyId: &key, SecretAccessKey: &secret, SessionToken: &token, Expiration: &credential.Expiration},
		AssumedRoleUser: &stsapi.AssumedRoleUser{Arn: &roleARN, AssumedRoleId: &roleID},
	}
}

// serviceRoleRequestContext projects an issued service session without retaining
// the deployer's identity or changing the originating causal event.
func serviceRoleRequestContext(ctx context.Context, credential identity.Credential, region, service string) (context.Context, *awswire.Error) {
	metadata, err := identity.RequestMetadata(credential, credential.AccessKeyID, region, uuid.NewString())
	if err != nil {
		return ctx, serviceRoleFailure(err)
	}
	metadata.ParentEventID = awsctx.FromContext(ctx).ParentEventID
	metadata.InvokedBy = service
	metadata.SourceIP, metadata.UserAgent = service, service
	return awsctx.WithMetadata(ctx, metadata), nil
}

func serviceRoleFailure(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return wire
	}
	return &awswire.Error{Code: "InternalFailure", Message: "Service-role authority transaction failed.", StatusCode: 500}
}
