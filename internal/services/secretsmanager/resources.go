package secretsmanager

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/secretsmanager"
)

var secretNamePattern = regexp.MustCompile(`^[a-zA-Z0-9/_+=.@-]+$`)
var secretARNSuffix = regexp.MustCompile(`-[a-zA-Z0-9]{6}$`)

func resolveSecret(r Reader, raw string) (SecretRecord, error) {
	if raw == "" || len(raw) > 2048 {
		return SecretRecord{}, failure("InvalidParameterException", "SecretId must contain between 1 and 2048 characters.")
	}
	scope := scopeFor(r.Context())
	name := raw
	full := false
	if strings.HasPrefix(raw, "arn:") {
		parts := strings.SplitN(raw, ":", 7)
		if len(parts) != 7 || parts[2] != "secretsmanager" || parts[5] != "secret" || parts[1] != scope.Partition || parts[3] != scope.Region || parts[4] == "" {
			return SecretRecord{}, failure("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
		}
		scope.AccountID = parts[4]
		name = parts[6]
		full = secretARNSuffix.MatchString(name)
		if full {
			name = name[:len(name)-7]
		}
	}
	secret, err := r.Secret(SecretKey{Scope: scope, Name: name})
	if errors.Is(err, ErrNotFound) || err == nil && full && secret.ARN != raw {
		// Preserve only the unresolved authorization scope. The unknown suffix
		// is symbolic: broad six-character suffix grants apply, whereas exact
		// or restricted suffix grants cannot identify a nonexistent secret.
		// This descriptor is never retained or returned as a secret resource.
		missing := SecretRecord{Key: SecretKey{Scope: scope, Name: name}, ARN: raw}
		if !strings.HasPrefix(raw, "arn:") {
			missing.ARN = fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:%s-??????", scope.Partition, scope.Region, scope.AccountID, name)
		}
		return missing, failure("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
	}
	return secret, err
}

func checkNotDeleted(secret SecretRecord) error {
	if secret.Deleted != nil {
		return failure("InvalidRequestException", "You can't perform this operation on the secret because it was marked for deletion.")
	}
	return nil
}

func checkPrimary(ctx context.Context, secret SecretRecord) error {
	if secret.PrimaryRegion != "" && secret.PrimaryRegion != secret.Key.Region {
		return failure("InvalidParameterException", "Operation not permitted on a replica secret. Call must be made in primary secret's region.")
	}
	if secret.OwningService != managedOwner(ctx) {
		return failure("InvalidRequestException", "Use the service that owns this secret to modify it.")
	}
	return nil
}

func checkWritable(ctx context.Context, secret SecretRecord) error {
	if err := checkNotDeleted(secret); err != nil {
		return err
	}
	return checkPrimary(ctx, secret)
}

func validateSecretMetadata(description *api.DescriptionType, key *api.KmsKeyIdType, kind *api.MedeaTypeType) error {
	if description != nil && len(*description) > 2048 {
		return failure("InvalidParameterException", "Description must not exceed 2048 characters.")
	}
	if key != nil && len(*key) > 2048 {
		return failure("InvalidParameterException", "KmsKeyId must not exceed 2048 characters.")
	}
	if kind != nil && len(*kind) > 256 {
		return failure("InvalidParameterException", "Type must not exceed 256 characters.")
	}
	if value(kind) != "" {
		// TODO: Comeback implement external secret partner ownership and synchronization.
		return failure("InvalidRequestException", "External secret partner management is not configured.")
	}
	return nil
}

func (s *Service) createSecret(tx Transaction, in *api.CreateSecretInput) (*api.CreateSecretOutput, error) {
	name := value(in.Name)
	if len(name) < 1 || len(name) > 512 || !validSecretName(tx.Context(), name) {
		return nil, failure("InvalidParameterException", "Invalid name. Must contain only alphanumeric characters or -/_+=.@.")
	}
	if err := validateSecretMetadata(in.Description, in.KmsKeyId, in.Type); err != nil {
		return nil, err
	}
	if err := validateSecretValue(in.SecretString, in.SecretBinary, false); err != nil {
		return nil, err
	}
	if err := validateVersionToken(in.ClientRequestToken); err != nil {
		return nil, err
	}
	if err := validateTags(in.Tags); err != nil {
		return nil, err
	}
	if in.AddReplicaRegions != nil && len(in.AddReplicaRegions) == 0 {
		return nil, failure("InvalidParameterException", "AddReplicaRegions must contain at least one region.")
	}
	now := s.clock.Now().UTC()
	scope := scopeFor(tx.Context())
	secret := SecretRecord{Key: SecretKey{Scope: scope, Name: name}, Created: now, Changed: now, KMSKeyID: value(in.KmsKeyId), Type: value(in.Type)}
	secret.OwningService = managedOwner(tx.Context())
	secret.ARN = fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:%s-%s", scope.Partition, scope.Region, scope.AccountID, name, identifier()[:6])
	existing, err := tx.Secret(secret.Key)
	if err == nil {
		secret.ARN, secret.Policy = existing.ARN, existing.Policy
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	noteSecretAudit(tx.Context(), secret)
	if in.Description != nil {
		secret.Description = ptr(value(in.Description))
	}
	if in.Tags != nil {
		secret.Tags = make(map[string]string, len(in.Tags))
		for _, tag := range in.Tags {
			secret.Tags[value(tag.Key)] = value(tag.Value)
		}
	}
	if secret.OwningService != "" {
		if secret.Tags == nil {
			secret.Tags = make(map[string]string)
		}
		secret.Tags["aws:secretsmanager:owningService"] = secret.OwningService
	}
	conditions := tagConditions(in.Tags)
	if conditions == nil {
		conditions = map[string][]string{}
	}
	conditions["secretsmanager:Name"] = []string{name}
	if in.Description != nil {
		conditions["secretsmanager:Description"] = []string{value(in.Description)}
	}
	if in.Type != nil {
		conditions["secretsmanager:Type"] = []string{value(in.Type)}
	}
	if in.ForceOverwriteReplicaSecret != nil {
		conditions["secretsmanager:ForceOverwriteReplicaSecret"] = []string{strconv.FormatBool(bool(*in.ForceOverwriteReplicaSecret))}
	}
	if in.KmsKeyId != nil {
		conditions["secretsmanager:KmsKeyId"] = []string{value(in.KmsKeyId)}
		if strings.HasPrefix(value(in.KmsKeyId), "arn:") {
			conditions["secretsmanager:KmsKeyArn"] = []string{value(in.KmsKeyId)}
		}
	}
	if len(in.AddReplicaRegions) > 0 {
		for _, region := range in.AddReplicaRegions {
			conditions["secretsmanager:AddReplicaRegions"] = append(conditions["secretsmanager:AddReplicaRegions"], value(region.Region))
		}
	}
	if err := s.authorize(tx, "CreateSecret", secret, conditions); err != nil {
		return nil, err
	}
	if len(in.Tags) > 0 {
		if err := s.authorize(tx, "TagResource", secret, conditions); err != nil {
			return nil, err
		}
	}
	if len(in.AddReplicaRegions) > 0 {
		if err := s.authorize(tx, "ReplicateSecretToRegions", secret, conditions); err != nil {
			return nil, err
		}
	}
	if err == nil {
		if existing.Deleted != nil {
			return nil, failure("InvalidRequestException", "You can't create this secret because a secret with this name is already scheduled for deletion.")
		}
		if in.ClientRequestToken != nil && (in.SecretString != nil || in.SecretBinary != nil) {
			version, lookupErr := tx.Version(VersionKey{Secret: existing.Key, ID: value(in.ClientRequestToken)})
			if lookupErr == nil {
				if err := s.sameSecretValue(tx, existing, version, in.SecretString, in.SecretBinary); err != nil {
					return nil, err
				}
				return &api.CreateSecretOutput{ARN: str[api.SecretARNType](existing.ARN), Name: str[api.SecretNameType](name), VersionId: str[api.SecretVersionIdType](version.Key.ID)}, nil
			}
			if !errors.Is(lookupErr, ErrNotFound) {
				return nil, lookupErr
			}
		}
		return nil, failure("ResourceExistsException", "The operation failed because the secret "+name+" already exists.")
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if in.KmsKeyId != nil {
		if err := s.validateKey(tx.Context(), secret, secret.KMSKeyID); err != nil {
			return nil, err
		}
	}
	if err := tx.PutSecret(secret); err != nil {
		return nil, err
	}
	out := &api.CreateSecretOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](name)}
	if in.SecretString != nil || in.SecretBinary != nil {
		version, err := s.storeSecretVersion(tx, secret, in.ClientRequestToken, in.SecretString, in.SecretBinary, nil)
		if err != nil {
			return nil, err
		}
		out.VersionId = str[api.SecretVersionIdType](version.Key.ID)
	}
	if len(in.AddReplicaRegions) > 0 {
		out.ReplicationStatus, err = s.replicate(tx, secret, in.AddReplicaRegions, in.ForceOverwriteReplicaSecret != nil && bool(*in.ForceOverwriteReplicaSecret))
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) updateSecret(tx Transaction, in *api.UpdateSecretInput) (*api.UpdateSecretOutput, error) {
	if err := validateSecretMetadata(in.Description, in.KmsKeyId, in.Type); err != nil {
		return nil, err
	}
	if err := validateSecretValue(in.SecretString, in.SecretBinary, false); err != nil {
		return nil, err
	}
	if err := validateVersionToken(in.ClientRequestToken); err != nil {
		return nil, err
	}
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	noteSecretAudit(tx.Context(), secret)
	conditions := map[string][]string{}
	if in.Description != nil {
		conditions["secretsmanager:Description"] = []string{value(in.Description)}
	}
	if in.Type != nil {
		conditions["secretsmanager:Type"] = []string{value(in.Type)}
	}
	if in.KmsKeyId != nil {
		conditions["secretsmanager:KmsKeyId"] = []string{value(in.KmsKeyId)}
		if strings.HasPrefix(value(in.KmsKeyId), "arn:") {
			conditions["secretsmanager:KmsKeyArn"] = []string{value(in.KmsKeyId)}
		}
	}
	if err := s.authorize(tx, "UpdateSecret", secret, conditions); err != nil {
		return nil, err
	}
	if err := checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	hasValue := in.SecretString != nil || in.SecretBinary != nil
	if hasValue && in.ClientRequestToken != nil {
		_, err := tx.Version(VersionKey{Secret: secret.Key, ID: value(in.ClientRequestToken)})
		if err == nil {
			return nil, versionExists(secret, value(in.ClientRequestToken))
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	if in.KmsKeyId != nil && value(in.KmsKeyId) != secret.KMSKeyID {
		if err := s.validateKey(tx.Context(), secret, value(in.KmsKeyId)); err != nil {
			return nil, err
		}
		if err := s.rewrapVersions(tx, secret, value(in.KmsKeyId)); err != nil {
			return nil, err
		}
		secret.KMSKeyID = value(in.KmsKeyId)
	}
	if in.Description != nil {
		secret.Description = ptr(value(in.Description))
	}
	if in.Type != nil {
		secret.Type = value(in.Type)
	}
	secret.Changed = s.clock.Now().UTC()
	if err := tx.PutSecret(secret); err != nil {
		return nil, err
	}
	out := &api.UpdateSecretOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name)}
	if hasValue {
		version, err := s.storeSecretVersion(tx, secret, in.ClientRequestToken, in.SecretString, in.SecretBinary, nil)
		if err != nil {
			return nil, err
		}
		out.VersionId = str[api.SecretVersionIdType](version.Key.ID)
	}
	if !hasValue {
		if err := s.refreshReplicas(tx, secret); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) deleteSecret(tx Transaction, in *api.DeleteSecretInput) (*api.DeleteSecretOutput, error) {
	force := in.ForceDeleteWithoutRecovery != nil && bool(*in.ForceDeleteWithoutRecovery)
	if in.ForceDeleteWithoutRecovery != nil && in.RecoveryWindowInDays != nil {
		return nil, failure("InvalidParameterException", "You can't use both ForceDeleteWithoutRecovery and RecoveryWindowInDays in the same request.")
	}
	days := int64(30)
	if in.RecoveryWindowInDays != nil {
		days = int64(*in.RecoveryWindowInDays)
	}
	if days < 7 || days > 30 {
		return nil, failure("InvalidParameterException", "RecoveryWindowInDays must be between 7 and 30 days.")
	}
	conditions := map[string][]string{}
	if in.RecoveryWindowInDays != nil {
		conditions["secretsmanager:RecoveryWindowInDays"] = []string{strconv.FormatInt(days, 10)}
	}
	if in.ForceDeleteWithoutRecovery != nil {
		conditions["secretsmanager:ForceDeleteWithoutRecovery"] = []string{strconv.FormatBool(force)}
	}
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		if !force || wireError(err).Code != "ResourceNotFoundException" {
			return nil, err
		}
		// Force deletion is idempotent even after the resource has disappeared.
		missing := SecretRecord{Key: SecretKey{Scope: scopeFor(tx.Context()), Name: value(in.SecretId)}, ARN: value(in.SecretId)}
		if !strings.HasPrefix(missing.ARN, "arn:") {
			missing.ARN = fmt.Sprintf("arn:%s:secretsmanager:%s:%s:secret:%s", missing.Key.Partition, missing.Key.Region, missing.Key.AccountID, missing.Key.Name)
		}
		if err := s.authorize(tx, "DeleteSecret", missing, conditions); err != nil {
			return nil, err
		}
		return &api.DeleteSecretOutput{}, nil
	}
	if err := s.authorize(tx, "DeleteSecret", secret, conditions); err != nil {
		return nil, err
	}
	if err := checkPrimary(tx.Context(), secret); err != nil {
		return nil, err
	}
	if err := s.checkPrimaryDeletion(tx, secret); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	deadline := now.Add(time.Duration(days) * 24 * time.Hour)
	if force {
		deadline = now
		if err := s.removeSecret(tx, secret); err != nil {
			return nil, err
		}
	} else {
		secret.Deleted, secret.DeleteAfter, secret.Changed = &now, &deadline, now
		if err := tx.PutSecret(secret); err != nil {
			return nil, err
		}
	}
	return &api.DeleteSecretOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name), DeletionDate: &deadline}, nil
}

func (s *Service) restoreSecret(tx Transaction, in *api.RestoreSecretInput) (*api.RestoreSecretOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(tx, "RestoreSecret", secret, nil); err != nil {
		return nil, err
	}
	if err := checkPrimary(tx.Context(), secret); err != nil {
		return nil, err
	}
	secret.Deleted, secret.DeleteAfter, secret.Changed = nil, nil, s.clock.Now().UTC()
	if err := tx.PutSecret(secret); err != nil {
		return nil, err
	}
	return &api.RestoreSecretOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name)}, nil
}
