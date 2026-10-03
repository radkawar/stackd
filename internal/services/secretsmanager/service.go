// Package secretsmanager owns regional secrets, immutable values and version labels.
package secretsmanager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	PolicyBinder authorization.PolicyBinder
	Recorder     apievents.Recorder
	Clock        clock.Clock
	Keys         DataKeys
	Rotation     Rotation
	Regions      RegionAccess
}

type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	binder     authorization.PolicyBinder
	recorder   apievents.Recorder
	clock      clock.Clock
	keys       DataKeys
	rotation   Rotation
	regions    RegionAccess
	jobs       *scheduler.Driver
	tokenKey   [32]byte
	operations map[string]func(context.Context) (any, *awswire.Error)
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
	if c.PolicyBinder == nil {
		c.PolicyBinder, _ = c.Authorizer.(authorization.PolicyBinder)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, binder: c.PolicyBinder, recorder: c.Recorder, clock: c.Clock, keys: c.Keys, rotation: c.Rotation, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.regions = c.Regions
	_, _ = rand.Read(s.tokenKey[:])
	s.jobs = scheduler.New(c.Clock, deletionJobs{s}, rotationJobs{s}, replicationJobs{s})
	register(s, "CreateSecret", s.createSecret)
	register(s, "UpdateSecret", s.updateSecret)
	register(s, "DeleteSecret", s.deleteSecret)
	register(s, "RestoreSecret", s.restoreSecret)
	register(s, "DescribeSecret", s.describeSecret)
	register(s, "ListSecrets", s.listSecrets)
	register(s, "GetSecretValue", s.getSecretValue)
	register(s, "BatchGetSecretValue", s.batchGetSecretValue)
	register(s, "PutSecretValue", s.putSecretValue)
	register(s, "ListSecretVersionIds", s.listSecretVersionIds)
	register(s, "UpdateSecretVersionStage", s.updateSecretVersionStage)
	register(s, "GetRandomPassword", s.getRandomPassword)
	register(s, "GetResourcePolicy", s.getResourcePolicy)
	register(s, "PutResourcePolicy", s.putResourcePolicy)
	register(s, "DeleteResourcePolicy", s.deleteResourcePolicy)
	register(s, "ValidateResourcePolicy", s.validateResourcePolicy)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "RotateSecret", s.rotateSecret)
	register(s, "CancelRotateSecret", s.cancelRotateSecret)
	register(s, "ReplicateSecretToRegions", s.replicateSecretToRegions)
	register(s, "RemoveRegionsFromReplication", s.removeRegionsFromReplication)
	register(s, "StopReplicationToReplica", s.stopReplicationToReplica)
	return s
}

func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for action := range s.operations {
		out = append(out, action)
	}
	slices.Sort(out)
	return out
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("secretsmanager")
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServiceError", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}

func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, request)
	action := string(request.Operation.Name)
	fn, ok := s.operations[action]
	if !ok {
		rejected := failure("NotImplementedException", "Secrets Manager operation is not implemented: "+action)
		rejected.StatusCode = http.StatusNotImplemented
		if err := s.RecordRequestError(ctx, request, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	return fn(ctx)
}

func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServiceError", "Missing generated request binding.")
		}
		return runCommand(s, ctx, action, in, fn)
	}
}

func runCommand[I, O any](s *Service, ctx context.Context, action string, in *I, fn func(Transaction, *I) (*O, error)) (*O, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	if s.recorder != nil {
		ctx = context.WithValue(ctx, secretAuditKey{}, &secretAudit{})
	}
	var out *O
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		var err error
		out, err = fn(tx, in)
		if err != nil {
			return err
		}
		return s.recordCall(tx.Context(), action, in, out, nil)
	})
	if err == nil {
		s.jobs.Wake()
		return out, nil
	}
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if err := s.recordCall(completion, action, in, nil, rejected); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}

func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested Secrets Manager operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		if invalid.TypeMismatch {
			return failure("SerializationException", invalid.Error())
		}
		return failure("ValidationException", invalid.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "InternalServiceError" {
		status = http.StatusInternalServerError
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	if err == nil {
		return nil
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		if wire.Code == "AccessDenied" {
			return failure("AccessDeniedException", wire.Message)
		}
		return wire
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
	}
	return failure("InternalServiceError", "Unable to access Secrets Manager state.")
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func ptr[T any](v T) *T          { return &v }
func str[T ~string](v string) *T { p := T(v); return &p }
func identifier() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	v := hex.EncodeToString(b[:])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
}
