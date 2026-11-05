package s3tables

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	Objects    WarehouseObjects
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	objects    WarehouseObjects
	operations map[string]func(context.Context) (any, *awswire.Error)
	flights    sync.Map
	wakeMu     sync.Mutex
	wake       func()
}

func New(c Config) *Service {
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, objects: c.Objects, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	registerOperations(s)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for name := range s.operations {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if f := s.operations[string(d.Operation.Name)]; f != nil {
		return f(ctx)
	}
	// TODO: Comeback implement remaining modeled policy, encryption configuration,
	// storage class, tagging, replication and maintenance operations before registration.
	e := failure("NotImplementedException", "This S3 Tables operation is not implemented", 501)
	if err := s.RecordRequestError(ctx, d, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}
func (*Service) RequestError(_ string, e error) *awswire.Error { return invalid(e.Error()) }
func (*Service) RequestErrorInput(op awscatalog.Operation, r awsapi.Request) any {
	v, e := api.NewInput(string(op.Name))
	if e != nil {
		return nil
	}
	m, _ := awscatalog.LookupService("s3tables")
	if awsapi.BindJSON(m, op.Input, r.JSON, v) != nil {
		return nil
	}
	return v
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerErrorException", "Missing generated request", 500))
		return
	}
	out, e := s.ExecuteCommand(r.Context(), d)
	if e != nil {
		awswire.JSONError(w, r, e)
		return
	}
	m, _ := awscatalog.LookupService("s3tables")
	body, err := awsapi.EncodeResponse(m, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	status := d.Operation.HTTPStatus
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	if status != http.StatusNoContent {
		_, _ = w.Write(body)
	}
}
func (s *Service) recordCall(ctx context.Context, name string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	m, _ := awscatalog.LookupService("s3tables")
	op, ok := m.Operation(name)
	if !ok {
		return nil
	}
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List")}
	call, e := p.Call(m, op, in, out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
func command[I, O any](s *Service, ctx context.Context, name string, in *I, f func(context.Context, Transaction, *I) (*O, error)) (*O, *awswire.Error) {
	ctx, e := apievents.Reserve(ctx)
	if e != nil {
		return nil, wireError(e)
	}
	var out *O
	e = s.repository.Attempt(ctx, func(tx Transaction) error {
		var e error
		out, e = f(tx.Context(), tx, in)
		if e != nil {
			return e
		}
		return s.recordCall(tx.Context(), name, in, out, nil)
	})
	if e == nil {
		return out, nil
	}
	rejected := wireError(e)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if e = s.recordCall(completion, name, in, nil, rejected); e != nil {
		return nil, wireError(e)
	}
	return nil, rejected
}
func bind[I, O any](s *Service, name string, f func(context.Context, *I) (*O, *awswire.Error)) {
	s.operations[name] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, invalid("Missing generated input")
		}
		return f(ctx, in)
	}
}
func (s *Service) authorize(ctx context.Context, action, arn string, conditions map[string][]string) error {
	now := s.clock.Now()
	e := s.authorizer.Authorize(ctx, authorization.Request{Action: "s3tables:" + action, ResourceARN: arn, ResourceAccountID: scopeFor(ctx).AccountID, Context: conditions, EvaluationTime: &now})
	if e == nil {
		return nil
	}
	if e.StatusCode == 403 {
		return failure("ForbiddenException", e.Message, 403)
	}
	return e
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func invalid(message string) *awswire.Error  { return failure("BadRequestException", message, 400) }
func conflict(message string) *awswire.Error { return failure("ConflictException", message, 409) }
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var e *awswire.Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, ErrNotFound) {
		return failure("NotFoundException", "S3 Tables resource not found", 404)
	}
	return failure("InternalServerErrorException", err.Error(), 500)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func text[T ~string](p **T, v string) { x := T(v); *p = &x }

var namePattern = regexp.MustCompile(`^[a-z0-9_]{1,255}$`)
var bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

func bucketARN(sc Scope, name string) string {
	return "arn:" + sc.Partition + ":s3tables:" + sc.Region + ":" + sc.AccountID + ":bucket/" + name
}
func (s *Service) bucket(ctx context.Context, r Reader, action, arn string, conditions map[string][]string) (Bucket, error) {
	sc := scopeFor(ctx)
	prefix := bucketARN(sc, "")
	if !strings.HasPrefix(arn, prefix) || !bucketPattern.MatchString(strings.TrimPrefix(arn, prefix)) {
		return Bucket{}, ErrNotFound
	}
	if e := s.authorize(ctx, action, arn, conditions); e != nil {
		return Bucket{}, e
	}
	return r.Bucket(sc, arn)
}

// Tokens are bound to the complete operation/scope/filter, never reusable across catalogs.
type pageCursor struct{ Binding, After string }

func page[T ~int32](binding string, token *api.NextToken, limit *T) (string, int, error) {
	n := 100
	if limit != nil {
		n = int(*limit)
	}
	if n < 1 || n > 1000 {
		return "", 0, invalid("Invalid maximum page size")
	}
	if token == nil {
		return "", n, nil
	}
	data, e := base64.RawURLEncoding.DecodeString(string(*token))
	if e != nil {
		return "", 0, invalid("Invalid continuation token")
	}
	var c pageCursor
	if json.Unmarshal(data, &c) != nil || c.Binding != binding {
		return "", 0, invalid("Invalid continuation token")
	}
	return c.After, n, nil
}
func next(binding, after string) *api.NextToken {
	b, _ := json.Marshal(pageCursor{binding, after})
	v := api.NextToken(base64.RawURLEncoding.EncodeToString(b))
	return &v
}
