package eventbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func (k BusKey) ARN() string {
	return "arn:" + k.Partition + ":events:" + k.Region + ":" + k.Account + ":event-bus/" + k.Name
}
func (k RuleKey) ARN() string {
	name := k.Name
	if k.Bus.Name != "default" {
		name = k.Bus.Name + "/" + name
	}
	return "arn:" + k.Bus.Partition + ":events:" + k.Bus.Region + ":" + k.Bus.Account + ":rule/" + name
}
func busKey(ctx context.Context, name string) (BusKey, *awswire.Error) {
	return resolveBus(scopeFor(ctx), name, false)
}

func resolveBus(scope Scope, name string, useEndpointRegion bool) (BusKey, *awswire.Error) {
	k := BusKey{Scope: scope, Name: name}
	if name == "" {
		k.Name = "default"
		return k, nil
	}
	if strings.HasPrefix(name, "arn:") {
		p := strings.SplitN(name, ":", 6)
		if len(p) != 6 || p[1] != k.Partition || p[2] != "events" || len(p[4]) != 12 || strings.Trim(p[4], "0123456789") != "" || !strings.HasPrefix(p[5], "event-bus/") {
			return k, failure("ValidationException", "Event bus ARN must identify an event bus in this partition and Region.")
		}
		if p[3] != k.Region && !useEndpointRegion {
			return k, failure("ValidationException", "Cross-region api call is not allowed.")
		}
		k.Account, k.Name = p[4], strings.TrimPrefix(p[5], "event-bus/")
	}
	if strings.Contains(k.Name, "/") {
		return k, unsupported("Partner event buses are not implemented.")
	}
	return k, nil
}
func (s *Service) bus(tx Transaction, k BusKey) (BusRecord, error) {
	v, err := tx.Bus(k)
	if errors.Is(err, ErrNotFound) && k.Name == "default" {
		now := s.clock.Now()
		v = BusRecord{Key: k, Created: now, Modified: now}
		err = tx.PutBus(v)
	}
	return v, err
}
func (s *Service) authorize(r Reader, action, arn string, tags map[string]string, conditions map[string][]string, bound authorization.BoundPolicy) error {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	for key, value := range tags {
		conditions["aws:ResourceTag/"+key] = []string{value}
	}
	now := s.clock.Now()
	request := authorization.Request{Action: "events:" + action, ResourceARN: arn, EvaluationTime: &now, Context: conditions, ResourcePolicies: []authorization.BoundPolicy{bound}}
	if action == "PutEvents" {
		// The catalog also describes PutRule's arrays. Each PutEvents entry
		// supplies one source/detail-type; native policies use StringEquals.
		request.ContextTypes = map[string]string{"events:source": "string", "events:detail-type": "string"}
	}
	if err := s.authorizer.Authorize(r.Context(), request); err != nil {
		return wireError(err)
	}
	return nil
}

func (s *Service) authorizeRule(r Reader, action string, rule RuleRecord, conditions map[string][]string) error {
	bus, err := r.Bus(rule.Key.Bus)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if conditions == nil {
		conditions = map[string][]string{}
	}
	if rule.CreatedBy != "" {
		conditions["events:creatorAccount"] = []string{rule.CreatedBy}
	}
	if rule.ManagedBy != "" {
		conditions["events:ManagedBy"] = []string{rule.ManagedBy}
	}
	return s.authorize(r, action, rule.Key.ARN(), rule.Tags, conditions, bus.Policy)
}

var invocationRoleResource = regexp.MustCompile(`^role/([!-~]+/)?[A-Za-z0-9_+=,.@-]{1,64}$`)

func validInvocationRole(rule RuleKey, roleARN string) bool {
	role, err := arn.Parse(roleARN)
	return err == nil && role.Partition == rule.Bus.Partition && role.Service == "iam" &&
		role.Region == "" && role.AccountID == rule.Bus.Account && invocationRoleResource.MatchString(role.Resource)
}

func (s *Service) passRole(ctx context.Context, roleARN, ruleARN string) *awswire.Error {
	now := s.clock.Now()
	return s.authorizer.Authorize(ctx, authorization.Request{
		Action: "iam:PassRole", ResourceARN: roleARN, EvaluationTime: &now,
		Context: map[string][]string{
			"iam:PassedToService":       {"events.amazonaws.com"},
			"iam:AssociatedResourceArn": {ruleARN},
		},
	})
}
func tagInput(tags api.TagList) (map[string]string, map[string][]string, *awswire.Error) {
	out := map[string]string{}
	conditions := map[string][]string{}
	for _, tag := range tags {
		k, v := value(tag.Key), value(tag.Value)
		if strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, nil, failure("ValidationException", "Tag keys beginning with aws: are reserved.")
		}
		out[k] = v
		conditions["aws:RequestTag/"+k] = []string{v}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], k)
	}
	if len(out) > 50 {
		return nil, nil, failure("LimitExceededException", "A resource can have at most 50 tags.")
	}
	return out, conditions, nil
}

type pageCursor struct{ Collection, After string }

func page[T any](rows []T, key func(T) string, collection string, limit *api.LimitMax100, token *api.NextToken, tokenErrorCode string) ([]T, *api.NextToken, *awswire.Error) {
	n := 100
	if limit != nil {
		n = int(*limit)
	}
	if n < 1 || n > 100 {
		return nil, nil, failure("ValidationException", "Limit must be between 1 and 100.")
	}
	after := ""
	if value(token) != "" {
		data, err := base64.RawURLEncoding.DecodeString(value(token))
		var c pageCursor
		if err != nil || json.Unmarshal(data, &c) != nil || c.Collection != collection {
			return nil, nil, failure(tokenErrorCode, "The pagination token is invalid.")
		}
		after = c.After
	}
	out := make([]T, 0)
	for _, v := range rows {
		if key(v) <= after {
			continue
		}
		if len(out) == n {
			data, _ := json.Marshal(pageCursor{collection, key(out[len(out)-1])})
			return out, str[api.NextToken](base64.RawURLEncoding.EncodeToString(data)), nil
		}
		out = append(out, v)
	}
	return out, nil, nil
}
