// Package account implements AWS Account Management state and permissions.
package account

import (
	"context"
	"io"
	"net/http"
	"slices"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/account"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/internal/services/organizations"
)

// OrganizationAccounts owns the account registry and resolves Organizations mode.
// The returned permission includes the management-owned ARN, organization
// conditions and service delegation. It does not replace IAM authorization.
type OrganizationAccounts interface {
	AccountManagementPermission(context.Context, string, string) (authorization.Request, error)
	AccountIdentity(context.Context, string, string) (organizations.AccountRecord, error)
	PutAccountName(context.Context, string, string, string) error
	CheckPrimaryEmail(context.Context, string, string) error
	PutPrimaryEmail(context.Context, string, string, string) error
}

// AccountCreationTimes shares the creation date owned by IAM with Account APIs.
// Initial metadata writes must join the repository context supplied by Account.
type AccountCreationTimes interface {
	AccountCreationTime(context.Context, string, string) (time.Time, error)
}

type Config struct {
	Repository    Repository
	APIEvents     apievents.Recorder
	Authorizer    authorization.Authorizer
	Organizations OrganizationAccounts
	CreationTimes AccountCreationTimes
	EmailSender   EmailSender
	Clock         clock.Clock
}

type Service struct {
	repository    Repository
	apiEvents     apievents.Recorder
	authorizer    authorization.Authorizer
	organizations OrganizationAccounts
	creationTimes AccountCreationTimes
	emailSender   EmailSender
	jobs          *scheduler.Driver
	clock         clock.Clock
	operations    map[string]func(context.Context) (any, error)
}

func New(config Config) *Service {
	if config.Clock == nil {
		config.Clock = clock.Real{}
	}
	if config.Repository == nil {
		config.Repository = NewMemoryRepository(nil)
	}
	if config.Authorizer == nil {
		config.Authorizer = authorization.NewWithClock(nil, nil, config.Clock)
	}
	s := &Service{repository: config.Repository, apiEvents: config.APIEvents, authorizer: config.Authorizer, organizations: config.Organizations, creationTimes: config.CreationTimes, emailSender: config.EmailSender, clock: config.Clock}
	s.operations = map[string]func(context.Context) (any, error){
		"GetRegionOptStatus":          bind(s, "GetRegionOptStatus", s.getRegionOptStatus),
		"ListRegions":                 bind(s, "ListRegions", s.listRegions),
		"EnableRegion":                bind(s, "EnableRegion", s.enableRegion),
		"DisableRegion":               bind(s, "DisableRegion", s.disableRegion),
		"GetContactInformation":       bind(s, "GetContactInformation", s.getContactInformation),
		"PutContactInformation":       bind(s, "PutContactInformation", s.putContactInformation),
		"GetAlternateContact":         bind(s, "GetAlternateContact", s.getAlternateContact),
		"PutAlternateContact":         bind(s, "PutAlternateContact", s.putAlternateContact),
		"DeleteAlternateContact":      bind(s, "DeleteAlternateContact", s.deleteAlternateContact),
		"GetAccountInformation":       bind(s, "GetAccountInformation", s.getAccountInformation),
		"PutAccountName":              bind(s, "PutAccountName", s.putAccountName),
		"GetPrimaryEmail":             bind(s, "GetPrimaryEmail", s.getPrimaryEmail),
		"GetPrimaryEmailUpdateStatus": bind(s, "GetPrimaryEmailUpdateStatus", s.getPrimaryEmailUpdateStatus),
		"StartPrimaryEmailUpdate":     bind(s, "StartPrimaryEmailUpdate", s.startPrimaryEmailUpdate),
		"AcceptPrimaryEmailUpdate":    bind(s, "AcceptPrimaryEmailUpdate", s.acceptPrimaryEmailUpdate),
	}
	s.jobs = scheduler.New(config.Clock, primaryEmailJobs{s})
	s.jobs.Start()
	return s
}

// Close cancels and joins account jobs, including external email delivery.
func (s *Service) Close() error {
	s.jobs.Close()
	return nil
}

func bind[I any](s *Service, name string, handler func(context.Context, I) (any, error)) func(context.Context) (any, error) {
	return func(ctx context.Context) (any, error) {
		input, ok := awsapi.Input[I](ctx)
		var output any
		var err error
		if !ok {
			err = failure("InternalServerException", "Missing generated operation input.", 500)
		} else {
			output, err = handler(ctx, *input)
		}
		if err != nil {
			apiErr := accountError(err)
			if recordErr := s.recordAPICall(ctx, name, input, nil, apiErr); recordErr != nil {
				return nil, recordErr
			}
			return nil, apiErr
		}
		// GetAccountInformation owns a write transaction for joined IAM
		// creation metadata and records there despite its read-only category.
		switch name {
		case "GetRegionOptStatus", "ListRegions", "GetContactInformation", "GetAlternateContact", "GetPrimaryEmail", "GetPrimaryEmailUpdateStatus":
			err = s.recordAPICall(ctx, name, input, output, nil)
		}
		return output, err
	}
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
	model, _ := awscatalog.LookupService("account")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		operation, labels, found := model.MatchHTTPOperation(r.Method, r.URL.EscapedPath(), r.URL.Query(), r.Header)
		if !found {
			awswire.RESTJSONError(w, r, &model, failure("UnknownOperationException", "No operation at this HTTP method and path.", 404))
			return
		}
		body, err := io.ReadAll(r.Body)
		if err == nil {
			decoded, err = api.DecodeRequest(string(operation.Name), awsapi.Request{Body: body, Labels: labels, Query: r.URL.Query(), Header: r.Header})
		}
		if err != nil {
			// Failed decoding has no trusted generated input to project.
			apiErr := failure("ValidationException", "Invalid Account request.", 400)
			if recordErr := s.RecordRequestError(r.Context(), awsapi.DecodedRequest{Operation: operation}, apiErr); recordErr != nil {
				apiErr = accountError(recordErr)
			}
			awswire.RESTJSONError(w, r, &model, apiErr)
			return
		}
		r = r.WithContext(awsapi.WithDecodedRequest(r.Context(), decoded))
	}
	output, wire := s.ExecuteCommand(r.Context(), decoded)
	if wire != nil {
		awswire.RESTJSONError(w, r, &model, wire)
		return
	}
	response, err := awsapi.EncodeHTTPResponse(model, decoded.Operation, output)
	if err != nil {
		awswire.RESTJSONError(w, r, &model, failure("InternalServerException", "Unable to encode Account response.", 500))
		return
	}
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}

func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	action := string(decoded.Operation.Name)
	handler, ok := s.operations[action]
	if !ok {
		// TODO: Comeback implement GovCloud account associations with the Organizations provisioning workflow.
		apiErr := failure("UnknownOperationException", "Unsupported Account operation: "+action, 400)
		if err := s.RecordRequestError(ctx, decoded, apiErr); err != nil {
			apiErr = accountError(err)
		}
		return nil, apiErr
	}
	output, err := handler(ctx)
	if err != nil {
		return nil, accountError(err)
	}
	return output, nil
}

func failure(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}

func validation(field, message, reason string) *awswire.Error {
	return &awswire.Error{Code: "ValidationException", Message: message, StatusCode: 400, Reason: reason, Fields: []awswire.ValidationField{{Name: field, Message: message}}}
}

func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func ptr[T any](v T) *T { return &v }
