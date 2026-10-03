package secretsmanager

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awswire"
)

func validateVersionToken(token *api.ClientRequestTokenType) error {
	if token != nil && (len(*token) < 32 || len(*token) > 64) {
		return failure("InvalidParameterException", "ClientRequestToken must contain between 32 and 64 characters.")
	}
	return nil
}

func validateSecretValue(text *api.SecretStringType, binary api.SecretBinaryType, required bool) error {
	if required && text == nil && binary == nil {
		return failure("InvalidRequestException", "You must provide either SecretString or SecretBinary.")
	}
	if text != nil && binary != nil {
		return failure("InvalidParameterException", "You must provide either SecretString or SecretBinary, but not both.")
	}
	if text != nil && (len(*text) < 1 || len(*text) > 65536) || binary != nil && (len(binary) < 1 || len(binary) > 65536) {
		return failure("InvalidParameterException", "The secret value must contain between 1 and 65536 bytes.")
	}
	return nil
}

func versionExists(secret SecretRecord, token string) error {
	return failure("ResourceExistsException", "You can't use ClientRequestToken "+token+" because that value is already in use for a version of secret "+secret.ARN+".")
}

func (s *Service) sameSecretValue(r Reader, secret SecretRecord, version VersionRecord, text *api.SecretStringType, binary api.SecretBinaryType) error {
	if version.Binary != (binary != nil) {
		return versionExists(secret, version.Key.ID)
	}
	plain, err := s.openVersion(r, secret, version)
	if err != nil {
		return err
	}
	defer clear(plain)
	same := bytes.Equal(plain, binary)
	if text != nil {
		same = string(plain) == string(*text)
	}
	if !same {
		return versionExists(secret, version.Key.ID)
	}
	return nil
}

func stageOutput(stages []string) api.SecretVersionStagesType {
	if stages == nil {
		return nil
	}
	out := make(api.SecretVersionStagesType, len(stages))
	for i, stage := range stages {
		out[i] = api.SecretVersionStageType(stage)
	}
	return out
}

func removeStage(version *VersionRecord, stage string) {
	version.Stages = slices.DeleteFunc(version.Stages, func(candidate string) bool { return candidate == stage })
}

// assignStage maintains the single-owner invariant, including the implicit
// previous-version transition whenever AWSCURRENT moves to another version.
func assignStage(versions []VersionRecord, target int, stage string) {
	previous := -1
	for i := range versions {
		if i != target && slices.Contains(versions[i].Stages, stage) {
			removeStage(&versions[i], stage)
			previous = i
		}
	}
	if !slices.Contains(versions[target].Stages, stage) {
		versions[target].Stages = append(versions[target].Stages, stage)
	}
	if stage == "AWSCURRENT" && previous >= 0 {
		for i := range versions {
			removeStage(&versions[i], "AWSPREVIOUS")
		}
		versions[previous].Stages = append([]string{"AWSPREVIOUS"}, versions[previous].Stages...)
	}
}

func checkStageQuota(versions []VersionRecord) error {
	count := 0
	for _, version := range versions {
		count += len(version.Stages)
	}
	if count > 20 {
		return failure("LimitExceededException", "You exceeded the maximum number of staging labels for a secret.")
	}
	return nil
}

func (s *Service) storeSecretVersion(tx Transaction, secret SecretRecord, token *api.ClientRequestTokenType, text *api.SecretStringType, binary api.SecretBinaryType, stages api.SecretVersionStagesType) (VersionRecord, error) {
	if err := validateVersionToken(token); err != nil {
		return VersionRecord{}, err
	}
	if err := validateSecretValue(text, binary, true); err != nil {
		return VersionRecord{}, err
	}
	if stages != nil && (len(stages) == 0 || len(stages) > 20) {
		return VersionRecord{}, failure("InvalidParameterException", "VersionStages must contain between 1 and 20 staging labels.")
	}
	for _, stage := range stages {
		if len(stage) == 0 || len(stage) > 256 {
			return VersionRecord{}, failure("InvalidParameterException", "A staging label must contain between 1 and 256 characters.")
		}
	}
	id := value(token)
	if token == nil {
		id = identifier()
	}
	versions, err := tx.Versions(secret.Key)
	if err != nil {
		return VersionRecord{}, err
	}
	target := slices.IndexFunc(versions, func(v VersionRecord) bool { return v.Key.ID == id })
	fresh := target < 0
	fillPending := false
	if !fresh {
		keyIDs, valueErr := tx.VersionKeyIDs(versions[target].Key)
		if errors.Is(valueErr, ErrNotFound) || valueErr == nil && len(keyIDs) == 0 {
			work, workErr := tx.Rotation(secret.Key)
			if workErr != nil && !errors.Is(workErr, ErrNotFound) {
				return VersionRecord{}, workErr
			}
			if workErr != nil || work.ARN != secret.ARN || work.Token != id || !slices.Contains(versions[target].Stages, "AWSPENDING") {
				return VersionRecord{}, versionExists(secret, id)
			}
			fillPending = true
			versions[target].Binary = binary != nil
		} else {
			if valueErr != nil {
				return VersionRecord{}, valueErr
			}
			if err := s.sameSecretValue(tx, secret, versions[target], text, binary); err != nil {
				return VersionRecord{}, err
			}
			if stages == nil {
				return versions[target], nil
			}
		}
	}
	now := s.clock.Now().UTC()
	if fillPending {
		versions[target].Created = now
	}
	var expired []VersionKey
	if fresh {
		// Only deprecated versions older than a day are eligible for removal.
		// A burst of new versions must reach the quota rather than lose values.
		for len(versions) >= 100 {
			oldest := -1
			for i, version := range versions {
				if len(version.Stages) == 0 && !version.Created.After(now.Add(-24*time.Hour)) && (oldest < 0 || version.Created.Before(versions[oldest].Created)) {
					oldest = i
				}
			}
			if oldest < 0 {
				return VersionRecord{}, failure("LimitExceededException", "You exceeded the maximum number of versions for a secret.")
			}
			expired = append(expired, versions[oldest].Key)
			versions = slices.Delete(versions, oldest, oldest+1)
		}
		target = len(versions)
		versions = append(versions, VersionRecord{Key: VersionKey{Secret: secret.Key, ID: id}, Binary: binary != nil, Created: now})
	}
	for _, stage := range stages {
		assignStage(versions, target, string(stage))
	}
	if fresh && (stages == nil || len(versions) == 1) {
		assignStage(versions, target, "AWSCURRENT")
	}
	if err := checkStageQuota(versions); err != nil {
		return VersionRecord{}, err
	}
	var plain []byte
	var sealed SealedValue
	if fresh || fillPending {
		plain = []byte(binary)
		if text != nil {
			plain = []byte(*text)
			defer clear(plain)
		}
		sealed, err = s.sealVersion(tx.Context(), secret, id, plain)
		if err != nil {
			return VersionRecord{}, err
		}
	}
	for _, key := range expired {
		if err := tx.DeleteVersion(key); err != nil {
			return VersionRecord{}, err
		}
	}
	for _, version := range versions {
		if err := tx.PutVersion(version); err != nil {
			return VersionRecord{}, err
		}
	}
	if fresh || fillPending {
		if err := tx.PutEncryptedVersion(versions[target].Key, []SealedValue{sealed}); err != nil {
			return VersionRecord{}, err
		}
	}
	secret.Changed = now
	if (fresh || fillPending) && secret.RotationEnabled != nil && *secret.RotationEnabled && slices.Contains(versions[target].Stages, "AWSCURRENT") && !slices.Contains(versions[target].Stages, "AWSPENDING") {
		if err := s.noteSecretRotation(tx, &secret, now); err != nil {
			return VersionRecord{}, err
		}
	}
	if err := tx.PutSecret(secret); err != nil {
		return VersionRecord{}, err
	}
	if fresh || fillPending {
		if err := s.replicateVersion(tx, secret, versions[target]); err != nil {
			return VersionRecord{}, err
		}
	}
	if err := s.refreshReplicas(tx, secret); err != nil {
		return VersionRecord{}, err
	}
	return versions[target], nil
}

func (s *Service) putSecretValue(tx Transaction, in *api.PutSecretValueInput) (*api.PutSecretValueOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	noteSecretAudit(tx.Context(), secret)
	// VersionStage is a condition for GetSecretValue and
	// UpdateSecretVersionStage, not for PutSecretValue's VersionStages list.
	if err := s.authorize(tx, "PutSecretValue", secret, nil); err != nil {
		return nil, err
	}
	if err := checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	if in.RotationToken != nil {
		if err := s.validateRotationToken(tx, secret, in); err != nil {
			return nil, err
		}
	}
	version, err := s.storeSecretVersion(tx, secret, in.ClientRequestToken, in.SecretString, in.SecretBinary, in.VersionStages)
	if err != nil {
		return nil, err
	}
	return &api.PutSecretValueOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name), VersionId: str[api.SecretVersionIdType](version.Key.ID), VersionStages: stageOutput(version.Stages)}, nil
}

func (s *Service) getSecretValue(tx Transaction, in *api.GetSecretValueInput) (*api.GetSecretValueOutput, error) {
	conditions := map[string][]string{}
	if in.VersionId != nil {
		conditions["secretsmanager:VersionId"] = []string{value(in.VersionId)}
	}
	if in.VersionStage != nil {
		conditions["secretsmanager:VersionStage"] = []string{value(in.VersionStage)}
	}
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		var missing *awswire.Error
		if secret.ARN != "" && errors.As(err, &missing) && missing.Code == "ResourceNotFoundException" {
			if denied := s.authorize(tx, "GetSecretValue", secret, conditions); denied != nil {
				return nil, denied
			}
		}
		return nil, err
	}
	if err := s.authorize(tx, "GetSecretValue", secret, conditions); err != nil {
		return nil, err
	}
	if err := checkNotDeleted(secret); err != nil {
		return nil, err
	}
	if in.VersionId != nil && (len(*in.VersionId) < 32 || len(*in.VersionId) > 64) || in.VersionStage != nil && (len(*in.VersionStage) < 1 || len(*in.VersionStage) > 256) {
		return nil, failure("InvalidParameterException", "Invalid VersionId or VersionStage.")
	}
	var version VersionRecord
	if in.VersionId != nil {
		version, err = tx.Version(VersionKey{Secret: secret.Key, ID: value(in.VersionId)})
		if errors.Is(err, ErrNotFound) {
			return nil, failure("ResourceNotFoundException", "Secrets Manager can't find the specified secret value for VersionId: "+value(in.VersionId))
		}
		if err != nil {
			return nil, err
		}
		if in.VersionStage != nil && !slices.Contains(version.Stages, value(in.VersionStage)) {
			return nil, failure("InvalidRequestException", "You provided a VersionStage that is not associated to the provided VersionId.")
		}
	} else {
		stage := value(in.VersionStage)
		if in.VersionStage == nil {
			stage = "AWSCURRENT"
		}
		versions, err := tx.Versions(secret.Key)
		if err != nil {
			return nil, err
		}
		index := slices.IndexFunc(versions, func(v VersionRecord) bool { return slices.Contains(v.Stages, stage) })
		if index < 0 {
			return nil, failure("ResourceNotFoundException", "Secrets Manager can't find the specified secret value for staging label: "+stage)
		}
		version = versions[index]
	}
	plain, err := s.openVersion(tx, secret, version)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ResourceNotFoundException", "Secrets Manager can't find the specified secret value for VersionId: "+version.Key.ID)
	}
	if err != nil {
		return nil, err
	}
	out := &api.GetSecretValueOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name), VersionId: str[api.SecretVersionIdType](version.Key.ID), CreatedDate: &version.Created, VersionStages: stageOutput(version.Stages)}
	if version.Binary {
		out.SecretBinary = api.SecretBinaryType(plain)
	} else {
		out.SecretString = str[api.SecretStringType](string(plain))
		clear(plain)
	}
	day := s.clock.Now().UTC().Truncate(24 * time.Hour)
	if version.LastAccessed == nil || !version.LastAccessed.Equal(day) {
		version.LastAccessed = &day
		if err := tx.PutVersion(version); err != nil {
			return nil, err
		}
	}
	if secret.LastAccessed == nil || !secret.LastAccessed.Equal(day) {
		secret.LastAccessed = &day
		if err := tx.PutSecret(secret); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) updateSecretVersionStage(tx Transaction, in *api.UpdateSecretVersionStageInput) (*api.UpdateSecretVersionStageOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	stage := value(in.VersionStage)
	if err := s.authorize(tx, "UpdateSecretVersionStage", secret, map[string][]string{"secretsmanager:VersionStage": {stage}}); err != nil {
		return nil, err
	}
	if err := checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	if len(stage) < 1 || len(stage) > 256 || in.MoveToVersionId == nil && in.RemoveFromVersionId == nil {
		return nil, failure("InvalidParameterException", "Provide VersionStage and at least one of MoveToVersionId or RemoveFromVersionId.")
	}
	for _, id := range []*api.SecretVersionIdType{in.MoveToVersionId, in.RemoveFromVersionId} {
		if id != nil && (len(*id) < 32 || len(*id) > 64) {
			return nil, failure("InvalidParameterException", "Version identifiers must contain between 32 and 64 characters.")
		}
	}
	versions, err := tx.Versions(secret.Key)
	if err != nil {
		return nil, err
	}
	owner, target, remove := -1, -1, -1
	for i, version := range versions {
		if slices.Contains(version.Stages, stage) {
			owner = i
		}
		if in.MoveToVersionId != nil && version.Key.ID == value(in.MoveToVersionId) {
			target = i
		}
		if in.RemoveFromVersionId != nil && version.Key.ID == value(in.RemoveFromVersionId) {
			remove = i
		}
	}
	if in.MoveToVersionId != nil && target < 0 || in.RemoveFromVersionId != nil && remove < 0 {
		return nil, failure("InvalidParameterException", "The specified version does not exist.")
	}
	if in.RemoveFromVersionId != nil && remove != owner {
		return nil, failure("InvalidParameterException", "The staging label is not attached to the version specified in RemoveFromVersionId.")
	}
	if target >= 0 && owner >= 0 && owner != target && in.RemoveFromVersionId == nil {
		return nil, failure("InvalidParameterException", fmt.Sprintf("The parameter RemoveFromVersionId can't be empty. Staging label %s is currently attached to version %s, so you must explicitly reference that version in RemoveFromVersionId.", stage, versions[owner].Key.ID))
	}
	if target >= 0 {
		assignStage(versions, target, stage)
	} else if remove >= 0 {
		removeStage(&versions[remove], stage)
	}
	if err := checkStageQuota(versions); err != nil {
		return nil, err
	}
	for _, version := range versions {
		if err := tx.PutVersion(version); err != nil {
			return nil, err
		}
	}
	secret.Changed = s.clock.Now().UTC()
	if err := tx.PutSecret(secret); err != nil {
		return nil, err
	}
	if err := s.refreshReplicas(tx, secret); err != nil {
		return nil, err
	}
	return &api.UpdateSecretVersionStageOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name)}, nil
}
