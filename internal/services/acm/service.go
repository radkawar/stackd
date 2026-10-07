package acm

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"slices"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/acm"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strings"
	"sync"
)

// DNSResolver resolves public CNAMEs through the configured authoritative DNS endpoint.
type DNSResolver interface {
	LookupCNAME(context.Context, string) (string, error)
}

// CertificateUsage consults current consumer identities in the shared transaction.
type CertificateUsage interface {
	CertificateUsers(context.Context, string, string, string, string, string) ([]string, error)
}
type Config struct {
	Repository Repository
	Authorizer authorization.Authorizer
	Recorder   apievents.Recorder
	Clock      clock.Clock
	DNS        DNSResolver
	Usage      CertificateUsage
}
type cachedTLS struct {
	version     uint64
	certificate tls.Certificate
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	dns        DNSResolver
	usage      CertificateUsage
	operations map[string]func(context.Context) (any, *awswire.Error)
	mu         sync.Mutex
	wake       func()
	cache      map[string]cachedTLS
}

func New(c Config) *Service {
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, dns: c.DNS, usage: c.Usage, operations: map[string]func(context.Context) (any, *awswire.Error){}, cache: map[string]cachedTLS{}}
	register(s, "RequestCertificate", s.requestCertificate)
	register(s, "DescribeCertificate", s.describeCertificate)
	register(s, "ListCertificates", s.listCertificates)
	register(s, "GetCertificate", s.getCertificate)
	register(s, "DeleteCertificate", s.deleteCertificate)
	register(s, "ImportCertificate", s.importCertificate)
	register(s, "ExportCertificate", s.exportCertificate)
	register(s, "RenewCertificate", s.renewCertificate)
	register(s, "UpdateCertificateOptions", s.updateOptions)
	register(s, "AddTagsToCertificate", s.addTags)
	register(s, "RemoveTagsFromCertificate", s.removeTags)
	register(s, "ListTagsForCertificate", s.listTags)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for op := range s.operations {
		out = append(out, op)
	}
	slices.Sort(out)
	return out
}
func (s *Service) JobSource() scheduler.Source { return s }
func (s *Service) SetWake(f func())            { s.mu.Lock(); s.wake = f; s.mu.Unlock() }
func (s *Service) notify() {
	s.mu.Lock()
	f := s.wake
	s.mu.Unlock()
	if f != nil {
		f()
	}
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, _ := awscatalog.LookupService("acm")
	req, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalFailure", "Missing request binding."))
		return
	}
	out, e := s.ExecuteCommand(r.Context(), req)
	if e != nil {
		awswire.JSONError(w, r, e)
		return
	}
	body, err := awsapi.EncodeResponse(m, req.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, wireError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (s *Service) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, r)
	if fn, ok := s.operations[string(r.Operation.Name)]; ok {
		return fn(ctx)
	}
	// TODO: Comeback implement email, private CA, ACME and remaining modeled ACM controls through their real owners.
	e := failure("UnknownOperationException", "This ACM operation is not supported.")
	if err := s.RecordRequestError(ctx, r, e); err != nil {
		return nil, wireError(err)
	}
	return nil, e
}
func register[I, O any](s *Service, op string, fn func(Transaction, *I) (*O, error)) {
	s.operations[op] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing request binding.")
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
			return s.recordCall(tx.Context(), op, in, out, nil)
		})
		if err == nil {
			s.notify()
			return out, nil
		}
		e := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err = s.recordCall(completion, op, in, nil, e); err != nil {
			return nil, wireError(err)
		}
		return nil, e
	}
}
func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(r.Operation.Name), r.Input, nil, e)
}
func (s *Service) RequestError(_ string, e error) *awswire.Error {
	if errors.Is(e, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "Unknown ACM operation.")
	}
	return failure("ValidationException", e.Error())
}
func (s *Service) recordCall(ctx context.Context, op string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	m, _ := awscatalog.LookupService("acm")
	o, ok := m.Operation(op)
	if !ok {
		return nil
	}
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(op, "Describe") || strings.HasPrefix(op, "List") || strings.HasPrefix(op, "Get"), Response: &awsapi.DocumentProjection{}}
	call, e := p.Call(m, o, in, out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func failure(code, msg string) *awswire.Error {
	return &awswire.Error{Code: code, Message: msg, StatusCode: http.StatusBadRequest}
}
func wireError(err error) *awswire.Error {
	var e *awswire.Error
	if errors.As(err, &e) {
		if e.Code == "AccessDenied" {
			return &awswire.Error{Code: "AccessDeniedException", Message: e.Message, StatusCode: http.StatusForbidden}
		}
		return e
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "Certificate does not exist in this account and region.")
	}
	return &awswire.Error{Code: "InternalFailure", Message: "ACM operation failed.", StatusCode: http.StatusInternalServerError}
}
func (s *Service) authorize(r Reader, op, arn string, tags map[string]string, requested api.TagList) error {
	if arn == "" {
		arn = "*"
	}
	conditions := map[string][]string{}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	request, _ := awsapi.FromContext(r.Context())
	switch in := request.Input.(type) {
	case *api.RequestCertificateRequest:
		conditions["acm:DomainNames"] = []string{value(in.DomainName)}
		for _, d := range in.SubjectAlternativeNames {
			conditions["acm:DomainNames"] = append(conditions["acm:DomainNames"], string(d))
		}
		conditions["acm:ValidationMethod"] = []string{value(in.ValidationMethod)}
		algorithm := value(in.KeyAlgorithm)
		if algorithm == "" {
			algorithm = "RSA_2048"
		}
		conditions["acm:KeyAlgorithm"] = []string{algorithm}
	case *api.AddTagsToCertificateRequest:
		requested = in.Tags
	case *api.RemoveTagsFromCertificateRequest:
		for _, t := range in.Tags {
			conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], value(t.Key))
		}
	}
	for _, t := range requested {
		conditions["aws:RequestTag/"+value(t.Key)] = []string{value(t.Value)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], value(t.Key))
	}
	now := s.clock.Now()
	if e := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "acm:" + op, ResourceARN: arn, Context: conditions, EvaluationTime: &now}); e != nil {
		return e
	}
	return nil
}
func (s *Service) owned(r Reader, op, arn string) (CertificateRecord, error) {
	c, e := r.Certificate(arn)
	if e != nil {
		return c, e
	}
	if c.Scope != scopeFor(r.Context()) {
		return CertificateRecord{}, ErrNotFound
	}
	if e = s.authorize(r, op, arn, c.Tags, nil); e != nil {
		return c, e
	}
	return c, observeCloudFormationOwner(r.Context(), c)
}
func (s *Service) users(r Reader, c CertificateRecord) ([]string, error) {
	if s.usage == nil {
		return nil, nil
	}
	return s.usage.CertificateUsers(r.Context(), c.Partition, c.AccountID, c.Region, c.ARN, c.ID)
}
