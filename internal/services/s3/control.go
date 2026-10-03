package s3

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3control"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Control exposes account and access-point APIs over the same S3 resource owner.
type Control struct{ s *Service }

type controlQueryKey struct{}

func (s *Service) Control() *Control { return &Control{s: s} }

func (*Control) Operations() []string {
	return []string{
		"CreateAccessPoint", "DeleteAccessPoint", "GetAccessPoint", "ListAccessPoints",
		"PutAccessPointPolicy", "GetAccessPointPolicy", "DeleteAccessPointPolicy", "GetAccessPointPolicyStatus",
		"TagResource", "UntagResource", "ListTagsForResource",
		"DeletePublicAccessBlock", "GetPublicAccessBlock", "PutPublicAccessBlock",
	}
}

func (*Control) RequestError(_ string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) || errors.Is(err, awsapi.ErrUnsupportedBinding) {
		return unsupported(err.Error())
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) {
		switch {
		case validation.Path == "AccountId":
			wire := denied()
			wire.AccountID = validation.HTTPValue
			return wire
		case validation.Path == "Tags" && validation.Constraint == "length.max":
			return failure("TooManyTags", "The maximum number of tags allowed on a resource is 50.", 400)
		case strings.HasPrefix(validation.Path, "Tags["):
			return failure("InvalidTag", "The tag key or value you have provided is invalid.", 400)
		case strings.HasPrefix(validation.Path, "TagKeys["):
			return failure("InvalidTag", "The tag key you have provided is invalid.", 400)
		}
	}
	return failure("InvalidRequest", err.Error(), http.StatusBadRequest)
}

func (p *Control) controlCall(ctx context.Context, action string) *apiCall {
	c := p.s.transferCall(ctx, action, "", "")
	c.service = "s3control"
	if request, ok := awsapi.FromContext(ctx); ok {
		c.additional["bytesTransferredIn"] = len(request.Body)
		query, _ := ctx.Value(controlQueryKey{}).(url.Values)
		switch action {
		case "CreateAccessPoint", "PutAccessPointPolicy", "TagResource":
			xmlAuditParameters(c, request.Body)
		case "ListAccessPoints":
			for _, name := range []string{"bucket", "nextToken", "maxResults"} {
				if values := query[name]; len(values) != 0 {
					c.params[name] = values[0]
				}
			}
		case "UntagResource":
			if keys := query["tagKeys"]; len(keys) == 1 {
				c.params["tagKeys"] = keys[0]
			} else if len(keys) != 0 {
				c.params["tagKeys"] = keys
			}
		}
		if in, ok := request.Input.(*api.PutPublicAccessBlockInput); ok && in.PublicAccessBlockConfiguration != nil {
			c.params["PublicAccessBlockConfiguration"] = in.PublicAccessBlockConfiguration
		}
	}
	return c
}

func (*Control) RequestErrorInput(operation awscatalog.Operation, request awsapi.Request) any {
	input, err := api.NewInput(string(operation.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("s3control")
	return bindRejectedInput(model, operation, request, input)
}

func (p *Control) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	if rejected, ok := request.Input.(*rejectedInput); ok {
		ctx = context.WithValue(ctx, requestHostKey{}, rejected.request.Host)
		ctx = context.WithValue(ctx, controlQueryKey{}, rejected.request.Query)
		request.Body = rejected.request.Body
		request.Input = rejected.input
	}
	ctx = awsapi.WithDecodedRequest(ctx, request)
	c := p.controlCall(ctx, string(request.Operation.Name))
	var account, arn string
	switch in := request.Input.(type) {
	case *api.TagResourceInput:
		account, arn = value(in.AccountId), value(in.ResourceArn)
	case *api.UntagResourceInput:
		account, arn = value(in.AccountId), value(in.ResourceArn)
	case *api.ListTagsForResourceInput:
		account, arn = value(in.AccountId), value(in.ResourceArn)
	}
	if arn != "" {
		if err := p.s.repository.View(ctx, func(reader Reader) error {
			_, err := p.taggedResource(reader, c, account, arn)
			if err != nil && wireError(err).StatusCode >= 500 {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return p.s.record(ctx, c, rejected)
}

func (p *Control) dispatch(ctx context.Context, decoded awsapi.DecodedRequest) (*preparedResponse, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	var response *preparedResponse
	var wire *awswire.Error
	switch in := decoded.Input.(type) {
	case *api.GetPublicAccessBlockInput:
		response, wire = p.getPublicAccessBlock(ctx, in)
	case *api.PutPublicAccessBlockInput:
		response, wire = p.putPublicAccessBlock(ctx, in)
	case *api.DeletePublicAccessBlockInput:
		response, wire = p.deletePublicAccessBlock(ctx, in)
	case *api.CreateAccessPointInput:
		response, wire = p.createAccessPoint(ctx, in)
	case *api.GetAccessPointInput:
		response, wire = p.getAccessPoint(ctx, in)
	case *api.ListAccessPointsInput:
		response, wire = p.listAccessPoints(ctx, in)
	case *api.DeleteAccessPointInput:
		response, wire = p.deleteAccessPoint(ctx, in)
	case *api.PutAccessPointPolicyInput:
		response, wire = p.putAccessPointPolicy(ctx, in)
	case *api.GetAccessPointPolicyInput:
		response, wire = p.getAccessPointPolicy(ctx, in)
	case *api.DeleteAccessPointPolicyInput:
		response, wire = p.deleteAccessPointPolicy(ctx, in)
	case *api.GetAccessPointPolicyStatusInput:
		response, wire = p.getAccessPointPolicyStatus(ctx, in)
	case *api.TagResourceInput:
		response, wire = p.tagResource(ctx, in)
	case *api.UntagResourceInput:
		response, wire = p.untagResource(ctx, in)
	case *api.ListTagsForResourceInput:
		response, wire = p.listTagsForResource(ctx, in)
	default:
		wire = unsupported("The requested S3 Control operation is not implemented.")
	}
	return response, wire
}

// ExecuteCommand returns the generated output retained by the HTTP dispatcher.
func (p *Control) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	response, wire := p.dispatch(ctx, decoded)
	if wire != nil || response == nil {
		return nil, wire
	}
	return response.modeledOutput(), wire
}

func (p *Control) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("s3control")
	decoded, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTXMLError(w, r, &model, failure("InternalError", "Missing generated S3 Control request binding.", http.StatusInternalServerError))
		return
	}
	ctx := context.WithValue(r.Context(), requestHostKey{}, r.Host)
	if r.URL.RawQuery != "" {
		ctx = context.WithValue(ctx, controlQueryKey{}, r.URL.Query())
	}
	response, wire := p.dispatch(ctx, decoded)
	if wire != nil {
		awswire.RESTXMLError(w, r, &model, wire)
		return
	}
	encoded := response.encodedResponse()
	for name, values := range encoded.Header {
		w.Header()[name] = values
	}
	requestID := awsctx.FromContext(r.Context()).RequestID
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("x-amz-id-2", awswire.S3HostID(requestID))
	w.WriteHeader(encoded.StatusCode)
	_, _ = w.Write(encoded.Body)
}
