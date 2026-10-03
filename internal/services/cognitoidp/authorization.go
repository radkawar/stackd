package cognitoidp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cognitoidp"
)

func (s *Service) authorize(tx Transaction, action, resource string, conditions map[string][]string) error {
	now := s.clock.Now()
	account := scopeFor(tx.Context()).AccountID
	if parts := strings.SplitN(resource, ":", 6); len(parts) == 6 {
		account = parts[4]
	}
	if denied := s.authorizer.Authorize(tx.Context(), authorization.Request{
		Action: action, ResourceARN: resource, ResourceAccountID: account,
		Context: conditions, EvaluationTime: &now,
	}); denied != nil {
		return failure("AccessDeniedException", denied.Message)
	}
	return nil
}

func (s *Service) adminPool(tx Transaction, action, poolID string) (PoolRecord, error) {
	return s.adminPoolConditions(tx, action, poolID, nil)
}

func (s *Service) adminPoolConditions(tx Transaction, action, poolID string, conditions map[string][]string) (PoolRecord, error) {
	key := PoolKey{Scope: scopeFor(tx.Context()), ID: poolID}
	// Authorize the requested scoped ARN even when the resource does not exist.
	pool, err := tx.Pool(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return PoolRecord{}, err
	}
	if err == nil {
		notePool(tx.Context(), key)
	}
	if conditions == nil {
		conditions = make(map[string][]string)
	}
	for k, v := range pool.Data.UserPoolTags {
		conditions["aws:ResourceTag/"+string(k)] = []string{string(v)}
	}
	if denied := s.authorize(tx, "cognito-idp:"+action, key.ARN(), conditions); denied != nil {
		return PoolRecord{}, denied
	}
	if err != nil {
		return PoolRecord{}, failure("ResourceNotFoundException", "User pool "+poolID+" does not exist.")
	}
	return pool, nil
}
func requestTagConditions(tags api.UserPoolTagsType) map[string][]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string][]string, len(tags)+1)
	for k, v := range tags {
		out["aws:RequestTag/"+string(k)] = []string{string(v)}
	}
	out["aws:TagKeys"] = tagKeys(tags)
	return out
}

func (s *Service) poolByARN(tx Transaction, action, arn string, conditions map[string][]string) (PoolRecord, error) {
	parts := strings.SplitN(arn, ":", 6)
	scope := scopeFor(tx.Context())
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "cognito-idp" || parts[3] != scope.Region || parts[4] != scope.AccountID || !strings.HasPrefix(parts[5], "userpool/") {
		return PoolRecord{}, failure("ResourceNotFoundException", "User pool does not exist.")
	}
	return s.adminPoolConditions(tx, action, strings.TrimPrefix(parts[5], "userpool/"), conditions)
}

func controlID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Tokens are cursors bound to the operation, owner and filter; the cursor names
// the last returned key rather than an offset that shifts when entries vanish.
func pageCursor(token, scope string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	var parts []string
	if err != nil || json.Unmarshal(raw, &parts) != nil || len(parts) != 2 || parts[0] != scope || parts[1] == "" {
		return "", failure("InvalidParameterException", "Invalid pagination token.")
	}
	return parts[1], nil
}
func nextPage(scope, last string) string {
	raw, _ := json.Marshal([]string{scope, last})
	return base64.RawURLEncoding.EncodeToString(raw)
}
func validatePoolTags(tags api.UserPoolTagsType) error {
	for key, val := range tags {
		if len(key) == 0 || len(key) > 128 || len(val) > 256 || strings.HasPrefix(strings.ToLower(string(key)), "aws:") {
			return failure("InvalidParameterException", "Invalid user pool tag.")
		}
	}
	return nil
}
func tagKeys(tags api.UserPoolTagsType) []string {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	return keys
}
