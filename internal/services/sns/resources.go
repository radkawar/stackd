package sns

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

var topicNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.fifo)?$`)
var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

func validTopicName(name string) bool {
	return len(name) <= 256 && topicNamePattern.MatchString(name)
}

func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
}

func topicKey(ctx context.Context, arn string) (TopicKey, *awswire.Error) {
	p := strings.Split(arn, ":")
	scope := scopeFor(ctx)
	if len(p) != 6 || p[0] != "arn" || p[1] != scope.Partition || p[2] != "sns" || p[3] != scope.Region || !accountPattern.MatchString(p[4]) {
		return TopicKey{}, failure("InvalidParameter", "Invalid parameter: TopicArn")
	}
	if !validTopicName(p[5]) {
		return TopicKey{}, failure("InvalidParameter", "Invalid parameter: TopicArn")
	}
	scope.AccountID = p[4]
	return TopicKey{Scope: scope, Name: p[5]}, nil
}

func validRoleARN(scope Scope, roleARN string) bool {
	parts := strings.Split(roleARN, ":")
	return len(parts) == 6 && parts[0] == "arn" && parts[1] == scope.Partition &&
		parts[2] == "iam" && parts[3] == "" && accountPattern.MatchString(parts[4]) &&
		strings.HasPrefix(parts[5], "role/") && len(parts[5]) > 5
}

func (s *Service) authorize(r Reader, action, arn string, tags map[string]string, conditions map[string][]string, bound authorization.BoundPolicy) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for key, v := range tags {
		conditions["aws:ResourceTag/"+key] = []string{v}
	}
	// SourceOwner is a legacy SNS service context, not the IAM caller's account.
	// Only CloudWatch supplies it; S3 and EventBridge use SourceAccount/SourceArn.
	m := awsctx.FromContext(r.Context())
	if action == "Publish" && m.ServicePrincipal.Name == "cloudwatch.amazonaws.com" {
		conditions["aws:SourceOwner"] = []string{m.AccountID}
	}
	return s.authorizeRequest(r.Context(), authorization.Request{Action: "sns:" + action, ResourceARN: arn, Context: conditions, ResourcePolicies: []authorization.BoundPolicy{bound}})
}

func (s *Service) authorizeRequest(ctx context.Context, request authorization.Request) error {
	now := s.clock.Now()
	request.EvaluationTime = &now
	if err := s.authorizer.Authorize(ctx, request); err != nil {
		if err.Code == "AccessDenied" {
			wire := failure("AuthorizationError", err.Message, 403)
			wire.Cause = err
			return wire
		}
		return err
	}
	return nil
}

func tagInput(tags api.TagList) (map[string]string, map[string][]string, *awswire.Error) {
	out := make(map[string]string, len(tags))
	conditions := map[string][]string{}
	for _, tag := range tags {
		key, v := value(tag.Key), value(tag.Value)
		if tag.Key == nil || tag.Value == nil || !validTagKey(key) || !utf8.ValidString(v) || utf8.RuneCountInString(v) > 256 {
			return nil, nil, failure("InvalidParameter", "Invalid tag key or value.")
		}
		if _, exists := out[key]; exists {
			return nil, nil, failure("InvalidParameter", "Duplicate tag keys are not allowed.")
		}
		out[key] = v
		conditions["aws:RequestTag/"+key] = []string{v}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], key)
	}
	if len(out) > 50 {
		return nil, nil, failure("TagLimitExceeded", "A topic can have at most 50 tags.")
	}
	return out, conditions, nil
}

func validTagKey(key string) bool {
	return utf8.ValidString(key) && utf8.RuneCountInString(key) >= 1 && utf8.RuneCountInString(key) <= 128 && !strings.HasPrefix(strings.ToLower(key), "aws:")
}

func (s *Service) renderPolicy(ctx context.Context, bound authorization.BoundPolicy) (string, error) {
	if bound.Document == "" {
		return "", nil
	}
	if s.binder == nil {
		return "", unsupported("Topic policy principal binding is not configured.")
	}
	return s.binder.RenderResourcePolicy(ctx, bound)
}

// Tokens follow the shared service convention and bind the cursor to its scope.
type pageCursor struct{ Collection, After string }

func decodeTopicCursor(token *api.NextToken, collection string) (string, *awswire.Error) {
	if token == nil {
		return "", nil
	}
	data, err := base64.RawURLEncoding.DecodeString(value(token))
	var cursor pageCursor
	if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Collection != collection || !validTopicName(cursor.After) {
		return "", failure("InvalidParameter", "Invalid parameter: NextToken")
	}
	return cursor.After, nil
}

func encodeTopicCursor(collection, after string) *api.NextToken {
	data, _ := json.Marshal(pageCursor{Collection: collection, After: after})
	return str[api.NextToken](base64.RawURLEncoding.EncodeToString(data))
}
