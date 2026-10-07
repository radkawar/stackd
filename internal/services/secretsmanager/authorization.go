package secretsmanager

import (
	"context"
	"errors"
	"maps"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// authorize retains the shared evaluator's identity, session, boundary and
// Organizations controls. In particular, a role grant and an exact session
// grant are not interchangeable, and IAM principal bindings survive deletion.
func (s *Service) authorize(r Reader, action string, secret SecretRecord, conditions map[string][]string) error {
	request := s.authorizationRequest(action, secret, conditions)
	if rejected := s.authorizer.Authorize(r.Context(), request); rejected != nil {
		return wireError(rejected)
	}
	return cloudFormationFence(r.Context(), action, secret)
}

func (s *Service) authorizationRequest(action string, secret SecretRecord, conditions map[string][]string) authorization.Request {
	context := make(map[string][]string, len(conditions)+2*len(secret.Tags)+4)
	maps.Copy(context, conditions)
	resource := secret.ARN
	if resource == "" {
		resource = "*"
	} else {
		// Native SecretId context is canonical even when the request used a name
		// or partial ARN. Version selectors belong to the operation and are
		// never inferred from the version ultimately selected.
		context["secretsmanager:SecretId"] = []string{secret.ARN}
		if secret.PrimaryRegion != "" {
			context["secretsmanager:SecretPrimaryRegion"] = []string{secret.PrimaryRegion}
		}
		if secret.RotationLambdaARN != "" {
			context["secretsmanager:resource/AllowRotationLambdaArn"] = []string{secret.RotationLambdaARN}
		}
		if secret.Type != "" {
			context["secretsmanager:resource/Type"] = []string{secret.Type}
		}
		for key, value := range secret.Tags {
			context["aws:ResourceTag/"+key] = []string{value}
			context["secretsmanager:ResourceTag/"+key] = []string{value}
		}
	}
	now := s.clock.Now()
	request := authorization.Request{
		Action:      "secretsmanager:" + strings.TrimPrefix(action, "secretsmanager:"),
		ResourceARN: resource, ResourceAccountID: secret.Key.AccountID,
		Context: context, EvaluationTime: &now,
	}
	if secret.Policy.Document != "" {
		request.ResourcePolicies = []authorization.BoundPolicy{secret.Policy}
	}
	return request
}

// ResolveRequestError preserves PutSecretValue's native admission order:
// bindable wire types, current resource authority, then modeled constraints.
// Rejected input is inspected only; it never enters command execution.
func (s *Service) ResolveRequestError(ctx context.Context, action string, request awsapi.Request, err error) *awswire.Error {
	var invalid *awsapi.ValidationError
	if action != "PutSecretValue" || !errors.As(err, &invalid) || invalid.TypeMismatch {
		return s.RequestError(action, err)
	}
	model, _ := awscatalog.LookupService("secretsmanager")
	operation, _ := model.Operation(action)
	var input api.PutSecretValueInput
	if bindErr := awsapi.BindJSON(model, operation.Input, request.JSON, &input); bindErr != nil {
		return s.RequestError(action, bindErr)
	}
	if authorityErr := s.repository.View(ctx, func(reader Reader) error {
		secret, lookupErr := resolveSecret(reader, value(input.SecretId))
		if lookupErr != nil {
			var rejected *awswire.Error
			if !errors.As(lookupErr, &rejected) || rejected.Code != "ResourceNotFoundException" && rejected.Code != "InvalidParameterException" {
				return lookupErr
			}
		}
		if secret.ARN == "" {
			secret.Key.Scope = scopeFor(reader.Context())
		}
		return s.authorize(reader, action, secret, nil)
	}); authorityErr != nil {
		return wireError(authorityErr)
	}
	return s.RequestError(action, err)
}

func tagConditions(tags api.TagListType) map[string][]string {
	conditions := make(map[string][]string, len(tags)+1)
	if len(tags) == 0 {
		return conditions
	}
	keys := make([]string, 0, len(tags))
	for _, tag := range tags {
		key := value(tag.Key)
		keys = append(keys, key)
		conditions["aws:RequestTag/"+key] = []string{value(tag.Value)}
	}
	conditions["aws:TagKeys"] = keys
	return conditions
}
