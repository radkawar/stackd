package secretsmanager

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awswire"
)

// Rotation is the Lambda consumer boundary. Validate checks current invocation
// authority without executing customer code and must join a borrowed transaction.
// Invoke runs customer code outside the Secrets Manager transaction; success
// means that the synchronous Lambda invocation completed without a function error.
type Rotation interface {
	Validate(ctx context.Context, lambdaARN, secretARN string) *awswire.Error
	Invoke(ctx context.Context, lambdaARN string, event RotationEvent) *awswire.Error
}

// RotationToken identifies this service-issued rotation at the external callback
// boundary. It is neither a Lambda execution receipt nor generic IAM attestation.
type RotationEvent struct {
	SecretID      string `json:"SecretId"`
	Token         string `json:"ClientRequestToken"`
	Step          string `json:"Step"`
	RotationToken string `json:"RotationToken"`
}

var rotationSteps = [...]string{"createSecret", "setSecret", "testSecret", "finishSecret"}

func rotationIncomplete() error {
	return failure("InvalidRequestException", "A previous rotation isn't complete. That rotation will be reattempted.")
}

func (s *Service) rotateSecret(tx Transaction, in *api.RotateSecretInput) (*api.RotateSecretOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	conditions := map[string][]string{}
	if in.RotationLambdaARN != nil {
		conditions["secretsmanager:RotationLambdaARN"] = []string{value(in.RotationLambdaARN)}
	}
	if in.RotateImmediately != nil {
		conditions["secretsmanager:RotateImmediately"] = []string{strconv.FormatBool(bool(*in.RotateImmediately))}
	}
	if err := s.authorize(tx, "RotateSecret", secret, conditions); err != nil {
		return nil, err
	}
	if err := checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	if err := validateVersionToken(in.ClientRequestToken); err != nil {
		return nil, err
	}
	if in.ExternalSecretRotationRoleArn != nil || in.ExternalSecretRotationMetadata != nil {
		// TODO: Comeback implement external secret partner rotation role and metadata.
		return nil, failure("InvalidRequestException", "External secret partner management is not configured.")
	}
	lambdaARN := secret.RotationLambdaARN
	if in.RotationLambdaARN != nil {
		lambdaARN = value(in.RotationLambdaARN)
	}
	if lambdaARN == "" {
		return nil, failure("InvalidRequestException", "No Lambda rotation function ARN is associated with this secret.")
	}
	parts := strings.SplitN(lambdaARN, ":", 7)
	if len(parts) != 7 || parts[0] != "arn" || parts[1] != secret.Key.Partition || parts[2] != "lambda" || parts[3] != secret.Key.Region || parts[4] == "" || parts[5] != "function" || parts[6] == "" || len(lambdaARN) > 2048 {
		return nil, failure("InvalidParameterException", "The rotation Lambda function ARN is invalid.")
	}
	rules, err := rotationRules(secret.RotationRules, in.RotationRules)
	if err != nil {
		return nil, err
	}
	schedule, err := parseRotationSchedule(rules)
	if err != nil {
		return nil, err
	}
	token := value(in.ClientRequestToken)
	if in.ClientRequestToken == nil {
		token = identifier()
	}
	versions, err := tx.Versions(secret.Key)
	if err != nil {
		return nil, err
	}
	for _, version := range versions {
		if slices.Contains(version.Stages, "AWSPENDING") && !slices.Contains(version.Stages, "AWSCURRENT") && version.Key.ID != token {
			return nil, rotationIncomplete()
		}
	}
	work, workErr := tx.Rotation(secret.Key)
	if workErr != nil && !errors.Is(workErr, ErrNotFound) {
		return nil, workErr
	}
	if workErr == nil && work.ARN == secret.ARN && work.Token != token && work.Due.Before(work.Deadline) {
		return nil, rotationIncomplete()
	}
	if s.rotation == nil {
		return nil, failure("InvalidRequestException", "Lambda rotation is not configured.")
	}
	if rejected := s.rotation.Validate(tx.Context(), lambdaARN, secret.ARN); rejected != nil {
		return nil, rejected
	}
	out := &api.RotateSecretOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name), VersionId: str[api.SecretVersionIdType](token)}
	// A request token is the version identity. Replays never restart a callback
	// or overwrite a completed or canceled version with a second rotation.
	if slices.ContainsFunc(versions, func(v VersionRecord) bool { return v.Key.ID == token }) {
		return out, nil
	}
	now := s.clock.Now().UTC()
	testOnly := in.RotateImmediately != nil && !bool(*in.RotateImmediately)
	secret.RotationLambdaARN, secret.RotationRules, secret.RotationEnabled = lambdaARN, rules, ptr(true)
	anchor := now
	if testOnly {
		anchor = secret.Created
		if secret.LastRotated != nil {
			anchor = *secret.LastRotated
		} else {
			for _, version := range versions {
				if slices.Contains(version.Stages, "AWSCURRENT") {
					anchor = version.Created
					break
				}
			}
		}
	}
	if err := setRotationSchedule(&secret, schedule, anchor, now); err != nil {
		return nil, err
	}
	deadline := schedule.end(now.Truncate(time.Hour))
	if secret.RotationDue.Before(deadline) {
		deadline = *secret.RotationDue
	}
	if err := s.beginRotation(tx, &secret, versions, token, testOnly, now, deadline); err != nil {
		return nil, err
	}
	secret.Changed = now
	if err := tx.PutSecret(secret); err != nil {
		return nil, err
	}
	if err := s.refreshReplicas(tx, secret); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) beginRotation(tx Transaction, secret *SecretRecord, versions []VersionRecord, token string, testOnly bool, now, deadline time.Time) error {
	work := RotationRecord{Secret: secret.Key, ARN: secret.ARN, Token: token, InvocationToken: identifier(), TestOnly: testOnly, Due: now, Deadline: deadline}
	if testOnly {
		work.Step = 2
	}
	if err := tx.PutRotation(work); err != nil {
		return err
	}
	if testOnly {
		current := slices.IndexFunc(versions, func(v VersionRecord) bool { return slices.Contains(v.Stages, "AWSCURRENT") })
		if current < 0 {
			return failure("InvalidRequestException", "The secret has no AWSCURRENT version to test.")
		}
		plain, err := s.openVersion(tx, *secret, versions[current])
		if err != nil {
			return err
		}
		defer clear(plain)
		var text *api.SecretStringType
		var binary api.SecretBinaryType
		if versions[current].Binary {
			binary = plain
		} else {
			text = str[api.SecretStringType](string(plain))
		}
		_, err = s.storeSecretVersion(tx, *secret, str[api.ClientRequestTokenType](token), text, binary, api.SecretVersionStagesType{"AWSPENDING"})
		return err
	}
	// Native immediate rotation exposes AWSPENDING before createSecret runs,
	// without copying AWSCURRENT or inventing an encrypted pending value.
	for len(versions) >= 100 {
		oldest := -1
		for i, version := range versions {
			if len(version.Stages) == 0 && !version.Created.After(now.Add(-24*time.Hour)) && (oldest < 0 || version.Created.Before(versions[oldest].Created)) {
				oldest = i
			}
		}
		if oldest < 0 {
			return failure("LimitExceededException", "You exceeded the maximum number of versions for a secret.")
		}
		if err := tx.DeleteVersion(versions[oldest].Key); err != nil {
			return err
		}
		versions = slices.Delete(versions, oldest, oldest+1)
	}
	pending := VersionRecord{Key: VersionKey{Secret: secret.Key, ID: token}, Created: now}
	versions = append(versions, pending)
	assignStage(versions, len(versions)-1, "AWSPENDING")
	if err := checkStageQuota(versions); err != nil {
		return err
	}
	for _, version := range versions {
		if err := tx.PutVersion(version); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) cancelRotateSecret(tx Transaction, in *api.CancelRotateSecretInput) (*api.CancelRotateSecretOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(tx, "CancelRotateSecret", secret, nil); err != nil {
		return nil, err
	}
	if err := checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	secret.RotationEnabled, secret.RotationDue, secret.NextRotation = ptr(false), nil, nil
	secret.Changed = s.clock.Now().UTC()
	// Cancellation revokes future callbacks; a running Lambda is not killed.
	// Its pending value and labels remain intact, as do the retained settings.
	if err := tx.DeleteRotation(secret.Key); err != nil {
		return nil, err
	}
	if err := tx.PutSecret(secret); err != nil {
		return nil, err
	}
	if err := s.refreshReplicas(tx, secret); err != nil {
		return nil, err
	}
	return &api.CancelRotateSecretOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name)}, nil
}

func (s *Service) validateRotationToken(tx Transaction, secret SecretRecord, in *api.PutSecretValueInput) error {
	token := value(in.RotationToken)
	invalid := failure("InvalidRequestException", "The rotation token is not valid for the active rotation of this secret.")
	if len(token) < 36 || len(token) > 256 {
		return failure("InvalidParameterException", "RotationToken must contain between 36 and 256 alphanumeric or hyphen characters.")
	}
	for _, ch := range token {
		if ch != '-' && !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') {
			return failure("InvalidParameterException", "RotationToken must contain between 36 and 256 alphanumeric or hyphen characters.")
		}
	}
	work, err := tx.Rotation(secret.Key)
	if errors.Is(err, ErrNotFound) {
		return invalid
	}
	if err != nil {
		return err
	}
	if secret.RotationEnabled == nil || !*secret.RotationEnabled || work.ARN != secret.ARN || work.Token != value(in.ClientRequestToken) || !s.clock.Now().Before(work.Deadline) || subtle.ConstantTimeCompare([]byte(token), []byte(work.InvocationToken)) != 1 {
		return invalid
	}
	version, err := tx.Version(VersionKey{Secret: secret.Key, ID: work.Token})
	if errors.Is(err, ErrNotFound) {
		return invalid
	}
	if err != nil {
		return err
	}
	if !slices.Contains(version.Stages, "AWSPENDING") {
		return invalid
	}
	return nil
}
