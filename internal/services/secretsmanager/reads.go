package secretsmanager

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	api "stackd/internal/awsapi/secretsmanager"
)

func secretVersionStages(r Reader, secret SecretRecord) (api.SecretVersionsToStagesMapType, error) {
	versions, err := r.Versions(secret.Key)
	if err != nil {
		return nil, err
	}
	var out api.SecretVersionsToStagesMapType
	for _, version := range versions {
		if len(version.Stages) == 0 {
			continue
		}
		if out == nil {
			out = make(api.SecretVersionsToStagesMapType)
		}
		out[api.SecretVersionIdType(version.Key.ID)] = stageOutput(version.Stages)
	}
	return out, nil
}

func secretMetadata(secret SecretRecord) api.DescribeSecretOutput {
	out := api.DescribeSecretOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name), CreatedDate: &secret.Created, LastChangedDate: &secret.Changed, LastAccessedDate: secret.LastAccessed, DeletedDate: secret.Deleted, LastRotatedDate: secret.LastRotated, NextRotationDate: secret.NextRotation, RotationRules: secret.RotationRules, Tags: secretTags(secret.Tags)}
	if secret.Description != nil {
		out.Description = str[api.DescriptionType](*secret.Description)
	}
	if secret.KMSKeyID != "" && secret.KMSKeyID != "DefaultEncryptionKey" {
		out.KmsKeyId = str[api.KmsKeyIdType](secret.KMSKeyID)
	}
	if secret.RotationEnabled != nil {
		out.RotationEnabled = ptr(api.RotationEnabledType(*secret.RotationEnabled))
	}
	if secret.RotationLambdaARN != "" {
		out.RotationLambdaARN = str[api.RotationLambdaARNType](secret.RotationLambdaARN)
	}
	if secret.PrimaryRegion != "" {
		out.PrimaryRegion = str[api.RegionType](secret.PrimaryRegion)
	}
	if secret.OwningService != "" {
		out.OwningService = str[api.OwningServiceType](secret.OwningService)
	}
	if secret.Type != "" {
		out.Type = str[api.MedeaTypeType](secret.Type)
	}
	return out
}

func (s *Service) describeSecret(tx Transaction, in *api.DescribeSecretInput) (*api.DescribeSecretOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(tx, "DescribeSecret", secret, nil); err != nil {
		return nil, err
	}
	out := secretMetadata(secret)
	out.VersionIdsToStages, err = secretVersionStages(tx, secret)
	if err != nil {
		return nil, err
	}
	out.ReplicationStatus, err = s.replicationStatus(tx, secret)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Cursors carry an exclusive ordered boundary, not a mutable list offset. The
// signature binds them to the operation, query, caller scope and incarnation.
type secretPageCursor struct {
	Scope                   Scope
	Operation, Query, After string
}

func secretPage[T any](s *Service, r Reader, operation string, query any, rows []T, key func(T) string, descending bool, size, maximum int, token *api.NextTokenType) ([]T, *api.NextTokenType, error) {
	if size < 1 || size > maximum {
		return nil, nil, failure("InvalidParameterException", fmt.Sprintf("MaxResults must be between 1 and %d.", maximum))
	}
	selection, err := json.Marshal(query)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(selection)
	expected := secretPageCursor{Scope: scopeFor(r.Context()), Operation: operation, Query: base64.RawURLEncoding.EncodeToString(digest[:])}
	after := ""
	if token != nil {
		encoded, signature, ok := strings.Cut(value(token), ".")
		body, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
		sig, sigErr := base64.RawURLEncoding.DecodeString(signature)
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		var cursor secretPageCursor
		if !ok || decodeErr != nil || sigErr != nil || !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(body, &cursor) != nil || cursor.After == "" {
			return nil, nil, failure("InvalidNextTokenException", "The pagination token is invalid.")
		}
		after, cursor.After = cursor.After, ""
		if cursor != expected {
			return nil, nil, failure("InvalidNextTokenException", "The pagination token belongs to a different request.")
		}
	}
	slices.SortFunc(rows, func(a, b T) int {
		order := strings.Compare(key(a), key(b))
		if descending {
			return -order
		}
		return order
	})
	start := 0
	if after != "" {
		for start < len(rows) {
			order := strings.Compare(key(rows[start]), after)
			if !descending && order > 0 || descending && order < 0 {
				break
			}
			start++
		}
	}
	end := min(start+size, len(rows))
	var next *api.NextTokenType
	if end < len(rows) {
		expected.After = key(rows[end-1])
		body, err := json.Marshal(expected)
		if err != nil {
			return nil, nil, err
		}
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(body)
		next = str[api.NextTokenType](base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	}
	return rows[start:end], next, nil
}

var filterValuePattern = regexp.MustCompile(`^!?[a-zA-Z0-9 :_@/+=.\-!]*$`)

func validateSecretFilters(filters api.FiltersListType) error {
	if len(filters) > 10 {
		return failure("InvalidParameterException", "No more than 10 filters may be supplied.")
	}
	for _, filter := range filters {
		switch value(filter.Key) {
		case "", "all", "name", "description", "tag-key", "tag-value", "primary-region", "owning-service":
		default:
			return failure("InvalidParameterException", "Invalid filter key: "+value(filter.Key))
		}
		if filter.Values != nil && (len(filter.Values) == 0 || len(filter.Values) > 10) {
			return failure("InvalidParameterException", "Filter Values must contain between 1 and 10 values.")
		}
		for _, term := range filter.Values {
			if len(term) > 512 || !filterValuePattern.MatchString(string(term)) {
				return failure("InvalidParameterException", "Invalid filter value.")
			}
		}
	}
	return nil
}

func searchWords(text string) []string {
	runes := []rune(text)
	var words []string
	start := -1
	for i, char := range runes {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			if start >= 0 {
				words = append(words, strings.ToLower(string(runes[start:i])))
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		previous := runes[i-1]
		if unicode.IsDigit(char) != unicode.IsDigit(previous) || unicode.IsUpper(char) && unicode.IsLower(previous) || unicode.IsUpper(char) && unicode.IsUpper(previous) && i+1 < len(runes) && unicode.IsLower(runes[i+1]) {
			words = append(words, strings.ToLower(string(runes[start:i])))
			start = i
		}
	}
	if start >= 0 {
		words = append(words, strings.ToLower(string(runes[start:])))
	}
	return words
}

func secretMatchesTerm(secret SecretRecord, key, term string) bool {
	switch key {
	case "name":
		return strings.HasPrefix(secret.Key.Name, term)
	case "description":
		return secret.Description != nil && strings.HasPrefix(strings.ToLower(*secret.Description), strings.ToLower(term))
	case "primary-region":
		return strings.HasPrefix(secret.PrimaryRegion, term)
	case "owning-service":
		return strings.HasPrefix(secret.OwningService, term)
	case "tag-key", "tag-value":
		for tag, value := range secret.Tags {
			if key == "tag-key" && strings.HasPrefix(tag, term) || key == "tag-value" && strings.HasPrefix(value, term) {
				return true
			}
		}
		return false
	default:
		words := searchWords(secret.Key.Name)
		if secret.Description != nil {
			words = append(words, searchWords(*secret.Description)...)
		}
		for tag, value := range secret.Tags {
			words = append(words, searchWords(tag)...)
			words = append(words, searchWords(value)...)
		}
		terms := searchWords(term)
		for _, word := range terms {
			if slices.Contains(words, word) {
				return true
			}
		}
		return len(terms) == 0
	}
}

func matchesSecretFilters(secret SecretRecord, filters api.FiltersListType) bool {
	for _, filter := range filters {
		if len(filter.Values) == 0 {
			continue
		}
		matched := false
		for _, raw := range filter.Values {
			term := string(raw)
			negative := strings.HasPrefix(term, "!")
			if negative {
				term = term[1:]
			}
			if secretMatchesTerm(secret, value(filter.Key), term) != negative {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func secretOrder(secret SecretRecord, by string) string {
	if by == "name" {
		return secret.Key.Name + "\x00" + secret.ARN
	}
	at := secret.Created
	if by == "last-changed-date" {
		at = secret.Changed
	} else if by == "last-accessed-date" {
		at = time.Time{}
		if secret.LastAccessed != nil {
			at = *secret.LastAccessed
		}
	}
	return at.UTC().Format("2006-01-02T15:04:05.000000000Z") + "\x00" + secret.ARN
}

func (s *Service) listSecrets(tx Transaction, in *api.ListSecretsInput) (*api.ListSecretsOutput, error) {
	if err := s.authorize(tx, "ListSecrets", SecretRecord{}, nil); err != nil {
		return nil, err
	}
	if err := validateSecretFilters(in.Filters); err != nil {
		return nil, err
	}
	by, order := value(in.SortBy), value(in.SortOrder)
	if by == "" {
		by = "created-date"
	}
	if order == "" {
		order = "asc"
	}
	if !slices.Contains([]string{"created-date", "last-accessed-date", "last-changed-date", "name"}, by) || order != "asc" && order != "desc" {
		return nil, failure("InvalidParameterException", "Invalid SortBy or SortOrder.")
	}
	rows, err := tx.Secrets(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	includeDeleted := in.IncludePlannedDeletion != nil && bool(*in.IncludePlannedDeletion)
	rows = slices.DeleteFunc(rows, func(secret SecretRecord) bool {
		return !includeDeleted && secret.Deleted != nil || !matchesSecretFilters(secret, in.Filters)
	})
	size := 10
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	query := struct {
		Filters        api.FiltersListType
		IncludeDeleted bool
		By, Order      string
	}{in.Filters, includeDeleted, by, order}
	rows, next, err := secretPage(s, tx, "ListSecrets", query, rows, func(secret SecretRecord) string { return secretOrder(secret, by) }, order == "desc", size, 100, in.NextToken)
	if err != nil {
		return nil, err
	}
	out := &api.ListSecretsOutput{SecretList: make(api.SecretListType, 0, len(rows)), NextToken: next}
	for _, secret := range rows {
		metadata := secretMetadata(secret)
		stages, err := secretVersionStages(tx, secret)
		if err != nil {
			return nil, err
		}
		out.SecretList = append(out.SecretList, api.SecretListEntry{ARN: metadata.ARN, Name: metadata.Name, Description: metadata.Description, KmsKeyId: metadata.KmsKeyId, RotationEnabled: metadata.RotationEnabled, RotationLambdaARN: metadata.RotationLambdaARN, RotationRules: metadata.RotationRules, LastRotatedDate: metadata.LastRotatedDate, LastChangedDate: metadata.LastChangedDate, LastAccessedDate: metadata.LastAccessedDate, NextRotationDate: metadata.NextRotationDate, DeletedDate: metadata.DeletedDate, Tags: metadata.Tags, SecretVersionsToStages: stages, OwningService: metadata.OwningService, CreatedDate: metadata.CreatedDate, PrimaryRegion: metadata.PrimaryRegion, Type: metadata.Type})
	}
	return out, nil
}

func (s *Service) listSecretVersionIds(tx Transaction, in *api.ListSecretVersionIdsInput) (*api.ListSecretVersionIdsOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(tx, "ListSecretVersionIds", secret, nil); err != nil {
		return nil, err
	}
	var versions []VersionRecord
	// Replica payloads remain readable by stage and ID, but native version-list
	// ownership stays with the primary until the replica is promoted.
	if secret.PrimaryRegion == "" || secret.PrimaryRegion == secret.Key.Region {
		versions, err = tx.Versions(secret.Key)
		if err != nil {
			return nil, err
		}
	}
	deprecated := in.IncludeDeprecated != nil && bool(*in.IncludeDeprecated)
	if !deprecated {
		versions = slices.DeleteFunc(versions, func(version VersionRecord) bool { return len(version.Stages) == 0 })
	}
	size := 100
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	query := struct {
		ARN        string
		Deprecated bool
	}{secret.ARN, deprecated}
	versions, next, err := secretPage(s, tx, "ListSecretVersionIds", query, versions, func(v VersionRecord) string {
		return v.Created.UTC().Format("2006-01-02T15:04:05.000000000Z") + "\x00" + v.Key.ID
	}, false, size, 100, in.NextToken)
	if err != nil {
		return nil, err
	}
	out := &api.ListSecretVersionIdsOutput{ARN: str[api.SecretARNType](secret.ARN), Name: str[api.SecretNameType](secret.Key.Name), Versions: make(api.SecretVersionsListType, 0, len(versions)), NextToken: next}
	for _, version := range versions {
		keys, err := tx.VersionKeyIDs(version.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		entry := api.SecretVersionsListEntry{VersionId: str[api.SecretVersionIdType](version.Key.ID), VersionStages: stageOutput(version.Stages), CreatedDate: &version.Created, LastAccessedDate: version.LastAccessed, KmsKeyIds: make(api.KmsKeyIdListType, len(keys))}
		for i, key := range keys {
			entry.KmsKeyIds[i] = api.KmsKeyIdType(key)
		}
		out.Versions = append(out.Versions, entry)
	}
	return out, nil
}

func (s *Service) batchGetSecretValue(tx Transaction, in *api.BatchGetSecretValueInput) (*api.BatchGetSecretValueOutput, error) {
	if err := s.authorize(tx, "BatchGetSecretValue", SecretRecord{}, nil); err != nil {
		return nil, err
	}
	if (in.SecretIdList == nil) == (in.Filters == nil) {
		return nil, failure("InvalidParameterException", "You must provide either SecretIdList or Filters, but not both.")
	}
	ids := in.SecretIdList
	out := &api.BatchGetSecretValueOutput{SecretValues: api.SecretValuesType{}, Errors: api.APIErrorListType{}}
	if ids != nil {
		if len(ids) < 1 || len(ids) > 20 || in.MaxResults != nil || in.NextToken != nil {
			return nil, failure("InvalidParameterException", "SecretIdList must contain 1 to 20 identifiers and cannot be combined with MaxResults or NextToken.")
		}
	} else {
		if err := s.authorize(tx, "ListSecrets", SecretRecord{}, nil); err != nil {
			return nil, err
		}
		if err := validateSecretFilters(in.Filters); err != nil {
			return nil, err
		}
		rows, err := tx.Secrets(scopeFor(tx.Context()))
		if err != nil {
			return nil, err
		}
		rows = slices.DeleteFunc(rows, func(secret SecretRecord) bool {
			return secret.Deleted != nil || !matchesSecretFilters(secret, in.Filters)
		})
		size := 20
		if in.MaxResults != nil {
			size = int(*in.MaxResults)
		}
		rows, out.NextToken, err = secretPage(s, tx, "BatchGetSecretValue", in.Filters, rows, func(secret SecretRecord) string { return secretOrder(secret, "created-date") }, false, size, 20, in.NextToken)
		if err != nil {
			return nil, err
		}
		ids = make(api.SecretIdListType, len(rows))
		for i, secret := range rows {
			ids[i] = api.SecretIdType(secret.ARN)
		}
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[string(id)] {
			continue
		}
		seen[string(id)] = true
		input := &api.GetSecretValueInput{SecretId: ptr(id)}
		entry, err := s.readBatchSecret(tx.Context(), input)
		if err != nil {
			wire := wireError(err)
			if wire.StatusCode >= 500 {
				return nil, err
			}
			out.Errors = append(out.Errors, api.APIErrorType{SecretId: ptr(id), ErrorCode: str[api.ErrorCode](wire.Code), Message: str[api.ErrorMessage](wire.Message)})
			continue
		}
		out.SecretValues = append(out.SecretValues, api.SecretValueEntry{ARN: entry.ARN, Name: entry.Name, VersionId: entry.VersionId, VersionStages: entry.VersionStages, SecretBinary: entry.SecretBinary, SecretString: entry.SecretString, CreatedDate: entry.CreatedDate})
	}
	return out, nil
}
