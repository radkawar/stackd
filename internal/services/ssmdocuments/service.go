package ssmdocuments

import (
	"context"
	"crypto/rand"
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

// PublicSharing reads the account/Region setting owned by the SSM settings service.
type PublicSharing interface {
	DocumentPublicSharingAllowed(context.Context) (bool, error)
}

type Config struct {
	Repository    Repository
	Authorizer    authorization.Authorizer
	Recorder      apievents.Recorder
	Clock         clock.Clock
	PublicSharing PublicSharing
}
type Service struct {
	repository    Repository
	authorizer    authorization.Authorizer
	recorder      apievents.Recorder
	clock         clock.Clock
	publicSharing PublicSharing
	jobs          *scheduler.Driver
	tokenKey      [32]byte
	operations    map[string]func(context.Context) (any, *awswire.Error)
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, publicSharing: c.PublicSharing, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	_, _ = rand.Read(s.tokenKey[:])
	s.jobs = scheduler.New(c.Clock, activationJobs{s})
	register(s, "CreateDocument", s.createDocument)
	register(s, "UpdateDocument", s.updateDocument)
	register(s, "UpdateDocumentDefaultVersion", s.updateDefault)
	register(s, "GetDocument", s.getDocument)
	register(s, "DescribeDocument", s.describeDocument)
	register(s, "ListDocuments", s.listDocuments)
	register(s, "ListDocumentVersions", s.listVersions)
	register(s, "DeleteDocument", s.deleteDocument)
	register(s, "ModifyDocumentPermission", s.modifyDocumentPermission)
	register(s, "DescribeDocumentPermission", s.describeDocumentPermission)
	register(s, "AddTagsToResource", s.addTagsToResource)
	register(s, "RemoveTagsFromResource", s.removeTagsFromResource)
	register(s, "ListTagsForResource", s.listTagsForResource)
	return s
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for k := range s.operations {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, request)
	fn, ok := s.operations[string(request.Operation.Name)]
	if !ok {
		return nil, failure("UnknownOperationException", "The operation is not owned by SSM documents.")
	}
	return fn(ctx)
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerError", "Missing generated request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var e error
			out, e = fn(tx, in)
			if e != nil {
				return e
			}
			return s.recordSuccess(tx, action, in, out)
		})
		if err == nil {
			s.jobs.Wake()
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err = s.record(completion, action, in, nil, rejected, ""); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.record(ctx, string(request.Operation.Name), request.Input, nil, rejected, "")
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerError", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("ssm")
	body, err := awsapi.EncodeResponse(model, request.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (*Service) RequestError(_ string, err error) *awswire.Error {
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
	return Scope{m.Partition, m.AccountID, m.Region}
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "InternalServerError" {
		status = http.StatusInternalServerError
	}
	if code == "NotImplementedException" {
		status = http.StatusNotImplemented
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	var w *awswire.Error
	if errors.As(err, &w) {
		if w.Code == "AccessDenied" {
			return failure("AccessDeniedException", w.Message)
		}
		return w
	}
	if errors.Is(err, ErrNotFound) {
		return failure("InvalidDocument", "The document does not exist.")
	}
	return failure("InternalServerError", "Unable to access document state.")
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
