package appsync

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"strings"
)

func registerControls(s *Service) {
	registerAPIs(s)
	registerKeys(s)
	registerDataSources(s)
	registerResolvers(s)
	registerFunctions(s)
	registerTags(s)
}
func register[I, O any](s *Service, action string, f func(context.Context, Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailureException", "Missing generated input", 500)
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = preflightMapping(ctx, in)
		if err == nil {
			err = s.repository.Attempt(ctx, func(t Transaction) error {
				var e error
				out, e = f(t.Context(), t, in)
				if e != nil {
					return e
				}
				return s.recordCall(t.Context(), action, in, out, nil)
			})
		}
		if err == nil {
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err = s.recordCall(completion, action, in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}

// Module initialization and export accessors execute customer JavaScript. Run
// them before opening the command transaction, with the caller's cancellation.
// Resource existence, dependencies and current authority are checked at commit.
func preflightMapping(ctx context.Context, input any) error {
	var code *api.Code
	switch in := input.(type) {
	case *api.CreateResolverRequest:
		code = in.Code
	case *api.UpdateResolverRequest:
		code = in.Code
	case *api.CreateFunctionRequest:
		code = in.Code
	case *api.UpdateFunctionRequest:
		code = in.Code
	default:
		return nil
	}
	if code == nil {
		return nil
	}
	if _, err := runMapping(ctx, value(code), "validate", map[string]any{}); err != nil {
		return bad(err.Error())
	}
	return nil
}

func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func bad(message string) error         { return failure("BadRequestException", message, 400) }
func unsupported(message string) error { return failure("NotImplementedException", message, 501) }
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var w *awswire.Error
	if errors.As(err, &w) {
		return w
	}
	if errors.Is(err, ErrNotFound) {
		return failure("NotFoundException", "Resource not found.", 404)
	}
	if errors.Is(err, ErrConflict) {
		return failure("ConcurrentModificationException", "Resource already exists or is in use.", 409)
	}
	return failure("InternalFailureException", err.Error(), 500)
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func text[T ~string](p **T, v string) { x := T(v); *p = &x }
func boolValue[T ~bool](p *T) bool    { return p != nil && bool(*p) }
func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}
func keyFor(ctx context.Context, id string) Key {
	m := awsctx.FromContext(ctx)
	return Key{m.Partition, m.AccountID, m.Region, id}
}
func (s *Service) permission(ctx context.Context, action, arn string, tags api.TagMap) error {
	// AWS's authorization reference does not support resource-level permissions
	// for these management actions. Scope is still enforced by repository keys.
	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_appsync.html
	switch action {
	case "CreateApiKey", "UpdateApiKey", "DeleteApiKey", "ListApiKeys",
		"CreateDataSource", "UpdateDataSource", "DeleteDataSource", "GetDataSource", "ListDataSources",
		"CreateResolver", "UpdateResolver", "DeleteResolver", "GetResolver", "ListResolvers", "ListResolversByFunction",
		"CreateFunction", "UpdateFunction", "DeleteFunction", "GetFunction", "ListFunctions",
		"StartSchemaCreation", "GetSchemaCreationStatus", "GetIntrospectionSchema":
		arn = "*"
		tags = nil
	}
	conditions := map[string][]string{}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+string(k)] = []string{string(v)}
	}
	return s.permissionContext(ctx, action, arn, conditions)
}
func (s *Service) permissionContext(ctx context.Context, action, arn string, conditions map[string][]string) error {
	if !strings.Contains(action, ":") {
		action = "appsync:" + action
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: action, ResourceARN: arn, Context: conditions, ContextTypes: map[string]string{"aws:TagKeys": "stringList"}, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) load(ctx context.Context, r Reader, id, action string) (APIRecord, error) {
	k := keyFor(ctx, id)
	p, err := r.API(k)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return p, err
	}
	if e := s.permission(ctx, action, k.ARN(), p.API.Tags); e != nil {
		return p, e
	}
	return p, err
}
func (s *Service) passRole(ctx context.Context, k Key, arn string) error {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != k.Partition || parts[2] != "iam" || parts[3] != "" || parts[4] != k.AccountID || !strings.HasPrefix(parts[5], "role/") {
		return bad("serviceRoleArn must identify an IAM role in the API account.")
	}
	return s.permissionContext(ctx, "iam:PassRole", arn, map[string][]string{"iam:PassedToService": {"appsync.amazonaws.com"}, "iam:AssociatedResourceArn": {k.ARN()}})
}

// Tokens contain an ordered cursor and exact request scope, not a mutable offset.
func page[T any](items []T, token *api.PaginationToken, max *api.MaxResults, scope string, id func(T) string) ([]T, *api.PaginationToken, error) {
	limit := 25
	if max != nil {
		limit = int(*max)
	}
	if limit < 1 || limit > 25 {
		return nil, nil, bad("maxResults must be between 1 and 25.")
	}
	cursor := ""
	if value(token) != "" {
		b, e := base64.RawURLEncoding.DecodeString(value(token))
		if e != nil {
			return nil, nil, bad("Invalid nextToken.")
		}
		prefix, after, ok := strings.Cut(string(b), "\x00")
		if !ok || prefix != scope {
			return nil, nil, bad("Invalid nextToken.")
		}
		cursor = after
	}
	start := 0
	for start < len(items) && id(items[start]) <= cursor {
		start++
	}
	end := min(start+limit, len(items))
	var next *api.PaginationToken
	if end < len(items) {
		text(&next, base64.RawURLEncoding.EncodeToString([]byte(scope+"\x00"+id(items[end-1]))))
	}
	return items[start:end], next, nil
}
