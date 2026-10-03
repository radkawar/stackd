package route53

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
	"stackd/clock"
	"stackd/compute/dns"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

type DNSAuthority interface {
	Register(dns.Resolver) (func(), error)
}

// AliasResolver reads the actual target owner; it must reject unknown zone IDs
// and names. It must not call back into this Route53 resolver.
type AliasResolver interface {
	// ValidateAlias reads retained owner identity only, joining admission's transaction.
	ValidateAlias(context.Context, AliasTarget, dnsmessage.Type) error
	ResolveAlias(context.Context, AliasTarget, dnsmessage.Type) ([]dnsmessage.Resource, error)
}
type Config struct {
	Repository   Repository
	Authorizer   authorization.Authorizer
	Recorder     apievents.Recorder
	Clock        clock.Clock
	DNSAuthority DNSAuthority
	Aliases      AliasResolver
}
type Service struct {
	repository Repository
	authorizer authorization.Authorizer
	recorder   apievents.Recorder
	clock      clock.Clock
	aliases    AliasResolver
	release    func()
	close      sync.Once
	operations map[string]func(context.Context) (any, *awswire.Error)
}

func New(c Config) (*Service, error) {
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, aliases: c.Aliases, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	register(s, "CreateHostedZone", s.createHostedZone)
	register(s, "GetHostedZone", s.getHostedZone)
	register(s, "ListHostedZones", s.listHostedZones)
	register(s, "ListHostedZonesByName", s.listHostedZonesByName)
	register(s, "GetHostedZoneCount", s.getHostedZoneCount)
	register(s, "UpdateHostedZoneComment", s.updateHostedZoneComment)
	register(s, "DeleteHostedZone", s.deleteHostedZone)
	register(s, "ChangeResourceRecordSets", s.changeResourceRecordSets)
	register(s, "ListResourceRecordSets", s.listResourceRecordSets)
	register(s, "GetChange", s.getChange)
	if c.DNSAuthority != nil {
		var err error
		s.release, err = c.DNSAuthority.Register(s)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}
func (s *Service) Close() error {
	s.close.Do(func() {
		if s.release != nil {
			s.release()
		}
	})
	return nil
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for k := range s.operations {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("route53")
	req, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTXMLError(w, r, &model, failure("InternalFailure", "Missing generated request binding."))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), req)
	if rejected != nil {
		awswire.RESTXMLError(w, r, &model, rejected)
		return
	}
	response, err := awsapi.EncodeHTTPResponse(model, req.Operation, out)
	if err != nil {
		awswire.RESTXMLError(w, r, &model, wireError(err))
		return
	}
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}
func (s *Service) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, r)
	fn, ok := s.operations[string(r.Operation.Name)]
	if !ok {
		// TODO: Comeback: health checks, DNSSEC, traffic policies, reusable delegation sets and private VPC hosted zones require their real owners.
		e := failure("NotImplemented", "This Route53 operation is not implemented.")
		if err := s.RecordRequestError(ctx, r, e); err != nil {
			return nil, wireError(err)
		}
		return nil, e
	}
	return fn(ctx)
}
func register[I, O any](s *Service, op string, fn func(Transaction, *I) (*O, error)) {
	s.operations[op] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalFailure", "Missing generated request binding.")
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
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if e := s.recordCall(completion, op, in, nil, rejected); e != nil {
			return nil, wireError(e)
		}
		return nil, rejected
	}
}
func (s *Service) RecordRequestError(ctx context.Context, r awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(r.Operation.Name), r.Input, nil, e)
}
func (s *Service) RequestError(_ string, e error) *awswire.Error {
	return failure("InvalidInput", e.Error())
}
func (s *Service) recordCall(ctx context.Context, op string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("route53")
	operation, ok := model.Operation(op)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(op, "Get") || strings.HasPrefix(op, "List"), Response: &awsapi.DocumentProjection{}}
	call, e := projection.Call(model, operation, in, out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	m := awsctx.FromContext(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, call)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID}
}
func (s *Service) authorize(r Reader, op, resource string, conditions map[string][]string) error {
	if resource == "" {
		resource = "*"
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "route53:" + op, ResourceARN: resource, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
func zoneARN(z Zone) string { return "arn:" + z.Partition + ":route53:::hostedzone/" + z.ID }
func cleanID(id string) string {
	return strings.TrimPrefix(strings.TrimPrefix(id, "/hostedzone/"), "/change/")
}
func failure(code, message string) *awswire.Error {
	status := 400
	switch code {
	case "AccessDenied":
		status = 403
	case "NoSuchHostedZone", "NoSuchChange":
		status = 404
	case "InternalFailure":
		status = 500
	case "NotImplemented":
		status = 501
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func wireError(err error) *awswire.Error {
	var w *awswire.Error
	if errors.As(err, &w) {
		return w
	}
	return failure("InternalFailure", "Unable to access Route53 state.")
}
func identifier(prefix string) string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return prefix + strings.ToUpper(hex.EncodeToString(b[:]))
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
