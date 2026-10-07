package cognitoidp

import (
	"context"
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
)

type Config struct {
	Repository     Repository
	Authorizer     authorization.Authorizer
	Recorder       apievents.Recorder
	Clock          clock.Clock
	PublicEndpoint string
	EmailSender    EmailSender
	EmailSetup     EmailSetup
}

type Service struct {
	repository     Repository
	authorizer     authorization.Authorizer
	recorder       apievents.Recorder
	clock          clock.Clock
	publicEndpoint string
	emailSender    EmailSender
	emailSetup     EmailSetup
	operations     map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, publicEndpoint: c.PublicEndpoint, emailSender: c.EmailSender, emailSetup: c.EmailSetup, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	registerControl(s)
	registerGroups(s)
	registerFederation(s)
	registerAuthentication(s)
	registerEmail(s)
	return s
}

func (s *Service) Operations() []string {
	names := make([]string, 0, len(s.operations))
	for name := range s.operations {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalErrorException", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("cognitoidp")
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
		rejected := failure("NotImplementedException", "Cognito operation is not implemented: "+action)
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
			return nil, failure("InternalErrorException", "Missing generated request binding.")
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
		ctx = context.WithValue(ctx, cognitoAuditKey{}, &cognitoAudit{})
	}
	var out *O
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		replay, finish, err := s.ownedCommand(tx, action, in)
		if err != nil {
			return err
		}
		if replay != nil {
			var ok bool
			if out, ok = replay.(*O); !ok {
				return failure("InternalErrorException", "Invalid owned command replay.")
			}
			return s.recordCall(tx.Context(), action, in, out, nil)
		}
		if out, err = fn(tx, in); err != nil {
			return err
		}
		if finish != nil {
			if err = finish(out); err != nil {
				return err
			}
		}
		return s.recordCall(tx.Context(), action, in, out, nil)
	})
	if err == nil {
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
		return failure("UnknownOperationException", "The requested Cognito operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		if invalid.TypeMismatch {
			return failure("SerializationException", invalid.Error())
		}
		return failure("InvalidParameterException", invalid.Error())
	}
	return failure("SerializationException", "Invalid request body.")
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "InternalErrorException" {
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
		return failure("ResourceNotFoundException", "Cognito resource does not exist.")
	}
	return failure("InternalErrorException", "Unable to access Cognito state.")
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func ptr[T any](v T) *T          { return &v }
func str[T ~string](v string) *T { p := T(v); return &p }
