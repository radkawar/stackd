package ssm

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awswire"
)

// Secrets reads through the existing Secrets Manager command and live authority.
// Parameter Store retains neither secret bytes nor reference metadata.
type Secrets interface {
	GetParameterSecret(context.Context, SecretReference) (ReferencedSecret, error)
}

type SecretReference struct {
	ID           string
	VersionID    string
	VersionStage string
}

type ReferencedSecret struct {
	ARN           string
	Name          string
	VersionID     string
	Value         *string
	Binary        []byte
	VersionStages []string
	Modified      time.Time
}

const secretReferencePrefix = "aws/reference/secretsmanager/"

var secretVersionIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var secretSourceEscapes = strings.NewReplacer("=", `\u003d`, "'", `\u0027`)

func isSecretReference(name string) bool {
	return strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(name), "/"), secretReferencePrefix)
}

// invalid distinguishes a per-name batch miss/invalid selector from a dependency
// authorization failure, which fails the entire GetParameters request on AWS.
func (s *Service) secretReferenceParameter(tx Transaction, raw, action string, decrypt bool) (out api.Parameter, invalid bool, err error) {
	name, selector := splitParameterSelector(raw)
	key := ParameterKey{Scope: scopeFor(tx.Context()), Name: name}
	if err := s.authorize(tx, action, ParameterRecord{Key: key, ARN: parameterARN(key)}, nil); err != nil {
		return out, false, err
	}
	if selector == ":" || strings.Count(selector, ":") > 1 {
		return out, true, failure("ValidationException", "Invalid parameter name. Please use correct syntax for referencing a version/label <name>:<version/label>")
	}
	if !decrypt {
		return out, true, failure("ValidationException", "WithDecryption flag must be True for retrieving a Secret Manager secret.")
	}
	if s.secrets == nil {
		return out, false, failure("UnsupportedOperation", "Secret references require the Secrets Manager authority.")
	}
	reference := SecretReference{ID: strings.TrimPrefix(strings.TrimPrefix(name, "/"), secretReferencePrefix)}
	if selector != "" {
		if secretVersionIDPattern.MatchString(selector[1:]) {
			reference.VersionID = selector[1:]
		} else {
			reference.VersionStage = selector[1:]
		}
	}
	secret, err := s.secrets.GetParameterSecret(tx.Context(), reference)
	if err != nil {
		var rejected *awswire.Error
		if !errors.As(err, &rejected) {
			return out, false, err
		}
		if rejected.Code == "ResourceNotFoundException" {
			suffix := selector
			if suffix == "" {
				suffix = "null"
			}
			return out, true, failure("ParameterNotFound", "An error occurred (ParameterNotFound) when referencing Secrets Manager: Secret "+strings.TrimPrefix(name, "/")+suffix+" not found.")
		}
		return out, false, failure("ValidationException", "An error occurred while calling one AWS dependency service.")
	}
	source, err := secretSourceResult(secret)
	if err != nil {
		return out, false, err
	}
	out = api.Parameter{
		ARN: new(api.String(secret.ARN)), Name: new(api.PSParameterName(name)),
		Type: new(api.ParameterType("SecureString")), Version: new(api.PSParameterVersion(0)),
		Value: (*api.PSParameterValue)(secret.Value), LastModifiedDate: new(secret.Modified),
		SourceResult: new(api.String(source)),
	}
	if selector != "" {
		out.Selector = new(api.PSParameterSelector(selector))
	}
	return out, false, nil
}

// SourceResult is the observed SSM dependency projection, not the public Secrets
// Manager JSON response. Binary data appears as its signed-byte buffer, while the
// outer Parameter intentionally has no Value.
func secretSourceResult(secret ReferencedSecret) (string, error) {
	type buffer struct {
		Bytes           []int8 `json:"hb"`
		Offset          int    `json:"offset"`
		ReadOnly        bool   `json:"isReadOnly"`
		BigEndian       bool   `json:"bigEndian"`
		NativeByteOrder bool   `json:"nativeByteOrder"`
		Mark            int    `json:"mark"`
		Position        int    `json:"position"`
		Limit           int    `json:"limit"`
		Capacity        int    `json:"capacity"`
		Address         int    `json:"address"`
	}
	source := struct {
		ARN       string   `json:"ARN"`
		Name      string   `json:"name"`
		VersionID string   `json:"versionId"`
		Value     *string  `json:"secretString,omitempty"`
		Binary    *buffer  `json:"secretBinary,omitempty"`
		Stages    []string `json:"versionStages"`
		Created   string   `json:"createdDate"`
	}{ARN: secret.ARN, Name: secret.Name, VersionID: secret.VersionID, Value: secret.Value, Stages: secret.VersionStages, Created: secret.Modified.UTC().Format("Jan 2, 2006, 3:04:05 PM")}
	if secret.Value == nil {
		bytes := make([]int8, len(secret.Binary))
		for i, b := range secret.Binary {
			bytes[i] = int8(b)
		}
		source.Binary = &buffer{Bytes: bytes, BigEndian: true, Mark: -1, Limit: len(bytes), Capacity: len(bytes), Address: 8}
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		return "", err
	}
	return secretSourceEscapes.Replace(string(encoded)), nil
}
