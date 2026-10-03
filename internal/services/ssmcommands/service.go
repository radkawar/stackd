package ssmcommands

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/scheduler"
	"stackd/internal/services/ssmdocuments"
)

type Documents interface {
	Resolve(context.Context, string, string) (ssmdocuments.Document, error)
}
type Credentials interface {
	Resolve(context.Context, string) (identity.Credential, error)
}

// ResourceGroups resolves current EC2 membership through the Resource Groups
// owner using the caller's transaction and ListGroupResources authority.
type ResourceGroups interface {
	Instances(context.Context, string) ([]string, error)
}
type Config struct {
	Repository     Repository
	Authorizer     authorization.Authorizer
	Recorder       apievents.Recorder
	Clock          clock.Clock
	Documents      Documents
	Instances      Instances
	Credentials    Credentials
	Notifications  Notifications
	ResourceGroups ResourceGroups
	Alarms         Alarms
}
type Service struct {
	repository     Repository
	authorizer     authorization.Authorizer
	recorder       apievents.Recorder
	clock          clock.Clock
	documents      Documents
	instances      Instances
	jobs           *scheduler.Driver
	credentials    Credentials
	notifications  Notifications
	resourceGroups ResourceGroups
	alarms         Alarms
	operations     map[string]func(context.Context) (any, *awswire.Error)
	tokenKey       [32]byte
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
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, documents: c.Documents, instances: c.Instances, credentials: c.Credentials, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.notifications = c.Notifications
	s.resourceGroups = c.ResourceGroups
	s.alarms = c.Alarms
	_, _ = rand.Read(s.tokenKey[:])
	s.jobs = scheduler.New(c.Clock, deadlineJobs{s}, notificationJobs{s}, alarmJobs{s})
	register(s, "SendCommand", s.sendCommand)
	register(s, "CancelCommand", s.cancelCommand)
	register(s, "ListCommands", s.listCommands)
	register(s, "ListCommandInvocations", s.listCommandInvocations)
	register(s, "GetCommandInvocation", s.getCommandInvocation)
	register(s, "DescribeInstanceInformation", s.describeInstanceInformation)
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
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	fn, ok := s.operations[string(request.Operation.Name)]
	if !ok {
		return nil, failure("NotImplementedException", "Unsupported managed execution operation.")
	}
	return fn(awsapi.WithDecodedRequest(ctx, request))
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerError", "Missing generated request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, s.wireError(ctx, err)
		}
		var out *O
		ctx, err = s.prepareAlarmRequest(ctx, in)
		if err == nil {
			err = s.repository.Attempt(ctx, func(tx Transaction) error {
				var err error
				out, err = fn(tx, in)
				if err != nil {
					return err
				}
				return s.record(tx.Context(), action, in, out, nil)
			})
		}
		if err == nil {
			s.jobs.Wake()
			return out, nil
		}
		rejected := s.wireError(ctx, err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		var dependency interface{ RecordRejection(context.Context) error }
		if errors.As(err, &dependency) {
			if recordErr := dependency.RecordRejection(completion); recordErr != nil {
				return nil, s.wireError(ctx, recordErr)
			}
		}
		if err = s.record(completion, action, in, nil, rejected); err != nil {
			return nil, s.wireError(ctx, err)
		}
		return nil, rejected
	}
}
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.record(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
func (s *Service) authorize(ctx context.Context, action, resource string, tags map[string]string, documentShare ...bool) error {
	conditions := make(map[string][]string, len(tags)*2)
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
		conditions["ssm:resourceTag/"+k] = []string{v}
	}
	now := s.clock.Now()
	account := scopeFor(ctx).AccountID
	builtin := false
	if parts := strings.SplitN(resource, ":", 6); len(parts) == 6 && parts[0] == "arn" {
		account = parts[4]
		if parts[2] == "ssm" && account == "" && parts[5] == "document/AWS-RunShellScript" {
			builtin = true
			account = ssmdocuments.BuiltinOwner(parts[1], parts[3], "AWS-RunShellScript")
		}
	}
	grant := builtin || len(documentShare) == 1 && documentShare[0]
	if e := s.authorizer.Authorize(ctx, authorization.Request{Action: action, ResourceARN: resource, ResourceAccountID: account, ResourceAccountGrant: grant, Context: conditions, EvaluationTime: &now}); e != nil {
		return s.wireError(ctx, e)
	}
	return nil
}
func (s *Service) wireError(ctx context.Context, err error) *awswire.Error {
	var e *awswire.Error
	if errors.As(err, &e) {
		if e.Code == "AccessDenied" {
			return failure("AccessDeniedException", e.Message)
		}
		return e
	}
	slog.ErrorContext(ctx, "SSM managed execution failed", "error", err)
	return failure("InternalServerError", "Unable to access managed execution state.")
}
func failure(code, message string) *awswire.Error {
	status := http.StatusBadRequest
	if code == "InternalServerError" {
		status = 500
	}
	if code == "NotImplementedException" {
		status = 501
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func keyFor(ctx context.Context, id string) Key { return Key{scopeFor(ctx), id} }
func instanceARN(k Key) string {
	return fmt.Sprintf("arn:%s:ec2:%s:%s:instance/%s", k.Partition, k.Region, k.AccountID, k.ID)
}
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func boolValue[T ~bool](v *T) bool { return v != nil && bool(*v) }
func terminal(status string) bool {
	switch status {
	case "Pending", "InProgress", "Delayed", "Cancelling":
		return false
	default:
		return true
	}
}
