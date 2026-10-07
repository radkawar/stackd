package secretsmanager

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awswire"
)

// CloudFormationOwnership is private native resource/edge authority. Claims on
// policy, rotation and target attachment edges never borrow the parent's claim.
type CloudFormationOwnership struct{ Owner, Token string }
type SecretTargetMetadata struct {
	Engine, Host                              string
	Port                                      float64
	DBInstanceIdentifier, DBClusterIdentifier string
}
type cloudFormationOwnershipKey struct{}
type secretTargetAttachmentKey struct{}

// WithSecretTargetAttachment selects the native atomic metadata merge for
// direct Cloud Control mutations without imposing a controller owner fence.
func WithSecretTargetAttachment(ctx context.Context, remove bool) context.Context {
	return context.WithValue(ctx, secretTargetAttachmentKey{}, remove)
}

type cloudFormationOwnershipContext struct {
	Claim          CloudFormationOwnership
	Aspect         string
	Create, Remove bool
}

func WithCloudFormationOwnership(ctx context.Context, claim CloudFormationOwnership, aspect string, create, remove bool) context.Context {
	return context.WithValue(ctx, cloudFormationOwnershipKey{}, cloudFormationOwnershipContext{claim, aspect, create, remove})
}
func cloudFormationOwner(ctx context.Context) (cloudFormationOwnershipContext, bool, error) {
	v, ok := ctx.Value(cloudFormationOwnershipKey{}).(cloudFormationOwnershipContext)
	if ok && (v.Claim.Owner == "" || v.Claim.Token == "") {
		return v, false, failure("InvalidRequestException", "The CloudFormation ownership identity is incomplete.")
	}
	return v, ok, nil
}
func aspectClaim(secret *SecretRecord, aspect string) *CloudFormationOwnership {
	switch aspect {
	case "secret":
		return &secret.Ownership
	case "policy":
		return &secret.PolicyOwnership
	case "rotation":
		return &secret.RotationOwnership
	case "attachment":
		return &secret.AttachmentOwnership
	}
	return nil
}

const cloudFormationMismatch = "The native secret resource or edge belongs to another CloudFormation incarnation."

func IsCloudFormationOwnershipMismatch(err error) bool {
	var rejected *awswire.Error
	return errors.As(err, &rejected) && rejected.Code == "InvalidRequestException" && rejected.Message == cloudFormationMismatch
}
func cloudFormationFence(ctx context.Context, action string, secret SecretRecord) error {
	v, owned, err := cloudFormationOwner(ctx)
	if err != nil || !owned {
		return err
	}
	if secret.ARN == "" {
		return nil
	}
	claim := aspectClaim(&secret, v.Aspect)
	if claim == nil {
		return failure("InvalidRequestException", "Unknown CloudFormation secret aspect.")
	}
	if *claim == v.Claim {
		return nil
	}
	if v.Create && *claim == (CloudFormationOwnership{}) && (action == "PutResourcePolicy" || action == "RotateSecret" || action == "PutSecretValue" || v.Aspect == "attachment" && action == "GetSecretValue") {
		return nil
	}
	return failure("InvalidRequestException", cloudFormationMismatch)
}

// admitCloudFormationAspect joins claim admission with the native edge write.
// Replays are observations, not repeated policy/rotation/attachment effects.
func admitCloudFormationAspect(ctx context.Context, secret *SecretRecord, aspect string, exists bool) (bool, error) {
	v, owned, err := cloudFormationOwner(ctx)
	if err != nil {
		return false, err
	}
	claim := aspectClaim(secret, aspect)
	if !owned {
		*claim = CloudFormationOwnership{}
		return false, nil
	}
	if v.Aspect != aspect {
		return false, nil
	}
	if v.Create {
		if *claim == v.Claim {
			return true, nil
		}
		if *claim != (CloudFormationOwnership{}) || exists {
			return false, failure("InvalidRequestException", cloudFormationMismatch)
		}
		*claim = v.Claim
	} else if *claim != v.Claim {
		return false, failure("InvalidRequestException", cloudFormationMismatch)
	}
	return false, nil
}

var secretConnectionKeys = []string{"engine", "host", "port", "dbInstanceIdentifier", "dbClusterIdentifier"}

func secretTargetMetadata(document map[string]any) SecretTargetMetadata {
	var out SecretTargetMetadata
	out.Engine, _ = document["engine"].(string)
	out.Host, _ = document["host"].(string)
	out.DBInstanceIdentifier, _ = document["dbInstanceIdentifier"].(string)
	out.DBClusterIdentifier, _ = document["dbClusterIdentifier"].(string)
	out.Port, _ = document["port"].(float64)
	return out
}
func (s *Service) secretDocument(r Reader, secret SecretRecord) (map[string]any, error) {
	versions, err := r.Versions(secret.Key)
	if err != nil {
		return nil, err
	}
	for _, version := range versions {
		if !slices.Contains(version.Stages, "AWSCURRENT") {
			continue
		}
		if version.Binary {
			return nil, failure("InvalidRequestException", "A target attachment requires a JSON object secret value.")
		}
		plain, err := s.openVersion(r, secret, version)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		var document map[string]any
		if json.Unmarshal(plain, &document) != nil || document == nil {
			return nil, failure("InvalidRequestException", "A target attachment requires a JSON object secret value.")
		}
		return document, nil
	}
	return map[string]any{}, nil
}
func (s *Service) prepareCloudFormationAttachment(tx Transaction, secret *SecretRecord, in *api.PutSecretValueInput) (bool, error) {
	v, owned, err := cloudFormationOwner(tx.Context())
	remove, attachment := tx.Context().Value(secretTargetAttachmentKey{}).(bool)
	if err != nil || !attachment && (!owned || v.Aspect != "attachment") {
		return false, err
	}
	if err := s.authorize(tx, "GetSecretValue", *secret, nil); err != nil {
		return false, err
	}
	current, err := s.secretDocument(tx, *secret)
	if err != nil {
		return false, err
	}
	metadata := secretTargetMetadata(current)
	replay, err := admitCloudFormationAspect(tx.Context(), secret, "attachment", metadata.DBInstanceIdentifier != "" || metadata.DBClusterIdentifier != "")
	if err != nil || replay {
		return replay, err
	}
	for _, key := range secretConnectionKeys {
		delete(current, key)
	}
	if remove || v.Remove {
		secret.AttachmentOwnership = CloudFormationOwnership{}
		secret.AttachmentMetadata = SecretTargetMetadata{}
	} else {
		var connection map[string]any
		if in.SecretString == nil || json.Unmarshal([]byte(*in.SecretString), &connection) != nil {
			return false, failure("InvalidParameterException", "The target connection metadata is invalid.")
		}
		for _, key := range secretConnectionKeys {
			if value, ok := connection[key]; ok {
				current[key] = value
			}
		}
		secret.AttachmentMetadata = secretTargetMetadata(current)
	}
	body, err := json.Marshal(current)
	if err != nil {
		return false, err
	}
	in.SecretString = str[api.SecretStringType](string(body))
	in.SecretBinary = nil
	return false, nil
}

// Native value edits reconcile against already-admitted plaintext, adding no
// read/KMS-decrypt permission requirement to an IAM-permitted native write.
func reconcileAttachmentValue(secret *SecretRecord, text *api.SecretStringType, binary api.SecretBinaryType) {
	if secret.AttachmentOwnership == (CloudFormationOwnership{}) {
		return
	}
	var metadata SecretTargetMetadata
	if text == nil || binary != nil || json.Unmarshal([]byte(*text), &metadata) != nil || metadata != secret.AttachmentMetadata {
		secret.AttachmentOwnership = CloudFormationOwnership{}
		secret.AttachmentMetadata = SecretTargetMetadata{}
	}
}
