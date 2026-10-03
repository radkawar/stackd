package sesv2

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"strings"
)

const classicNamespace = "http://ses.amazonaws.com/doc/2010-12-01/"

type classicContextKey struct{}

func isClassic(ctx context.Context) bool { v, _ := ctx.Value(classicContextKey{}).(bool); return v }

// ClassicService is the AWS Query frontend of the same SES domain. It owns no
// repository, scheduler or independent authorization snapshot.
type ClassicService struct {
	owner      *Service
	operations map[string]func(context.Context) (any, *awswire.Error)
}

func (s *Service) Classic() *ClassicService {
	c := &ClassicService{owner: s, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	c.registerIdentities()
	c.registerTemplates()
	c.registerConfigurations()
	c.registerSending()
	return c
}
func (c *ClassicService) Operations() []string {
	out := make([]string, 0, len(c.operations))
	for name := range c.operations {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
func registerClassic[I, O any](c *ClassicService, action string, fn func(Transaction, *I) (*O, error)) {
	registerOperation(c.owner, c.operations, action, fn, true)
}
func (c *ClassicService) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = context.WithValue(awsapi.WithDecodedRequest(ctx, d), classicContextKey{}, true)
	if fn := c.operations[string(d.Operation.Name)]; fn != nil {
		return fn(ctx)
	}
	// TODO: Comeback — classic receipt rules/inbound mail, custom verification templates,
	// DNS/DKIM and MAIL FROM, notification/event destinations, tracking, delivery options,
	// reputation metrics and sending quota enforcement require their actual shared owners.
	rejected := unsupported("SES operation is not implemented: " + string(d.Operation.Name))
	if err := c.owner.RecordRequestError(ctx, d, rejected); err != nil {
		return nil, classicError(string(d.Operation.Name), err)
	}
	return nil, rejected
}
func (c *ClassicService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.QueryError(w, r, classicNamespace, failure("InvalidParameterValue", "Missing generated request binding.", 400))
		return
	}
	out, rejected := c.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.QueryError(w, r, classicNamespace, rejected)
		return
	}
	model, _ := awscatalog.LookupService("ses")
	body, err := awsapi.EncodeResponse(model, d.Operation, out)
	if err != nil {
		awswire.QueryError(w, r, classicNamespace, classicError(string(d.Operation.Name), err))
		return
	}
	awswire.WriteQueryBytes(w, r, classicNamespace, string(d.Operation.Name), body)
}
func (*ClassicService) RequestError(action string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("InvalidAction", "Unknown SES operation.", 400)
	}
	return classicError(action, bad(err.Error()))
}
func (c *ClassicService) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return c.owner.RecordRequestError(context.WithValue(ctx, classicContextKey{}, true), d, e)
}
func classicError(action string, err error) *awswire.Error {
	e := wireError(err)
	code, status := e.Code, e.StatusCode
	switch code {
	case "AccessDeniedException":
		code = "AccessDenied"
	case "BadRequestException":
		code = "InvalidParameterValue"
	case "AlreadyExistsException":
		code = "AlreadyExists"
		if strings.Contains(action, "ConfigurationSet") {
			code = "ConfigurationSetAlreadyExists"
		}
	case "NotFoundException":
		code = "InvalidParameterValue"
		status = 400
		if strings.Contains(action, "Template") {
			code = "TemplateDoesNotExist"
		}
		if strings.Contains(action, "ConfigurationSet") {
			code = "ConfigurationSetDoesNotExist"
		}
	case "SendingPausedException":
		code = "AccountSendingPaused"
	case "InternalServiceErrorException":
		code = "InternalFailure"
	}
	return &awswire.Error{Code: code, Message: e.Message, StatusCode: status, Cause: e.Cause}
}
