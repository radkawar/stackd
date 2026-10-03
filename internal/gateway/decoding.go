package gateway

import (
	"context"
	"errors"
	"net/http"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// Some services distinguish modeled constraint failures by operation or field.
// The provider owns those wire errors for gateway and standalone requests.
type requestErrorMapper interface {
	RequestError(action string, err error) *awswire.Error
}

// Some native failures depend on resource authority or state before malformed
// input is considered. Resolution cannot admit a failed decode as a command.
type requestErrorResolver interface {
	ResolveRequestError(context.Context, string, awsapi.Request, error) *awswire.Error
}

// jsonRequestLimiter supplies an HTTP envelope limit that is not a modeled
// member constraint. It applies to original JSON, before typed decoding or
// service-owned batch routing, and rejects with an empty HTTP 413 response.
type jsonRequestLimiter interface {
	JSONRequestLimit(action string) int
}

// requestAdmitter owns service budgets after authentication but before generated
// validation. Rejections have no bound input to expose to audit or metrics.
type requestAdmitter interface {
	AdmitRequest(context.Context, string) *awswire.Error
}

// Sources own native audit projections for authenticated requests rejected before
// command dispatch. Unknown operation names have no modeled API outcome.
type requestErrorRecorder interface {
	RecordRequestError(context.Context, awsapi.DecodedRequest, *awswire.Error) error
}

// A service opts in only when native evidence retains modeled rejected fields.
// The input is for that service's redacting observer, never command dispatch.
type requestErrorInputBinder interface {
	RequestErrorInput(awscatalog.Operation, awsapi.Request) any
}

// Rejection metrics can measure authenticated wire input without exposing it to
// audit projection or admitting a command that failed generated validation.
type requestErrorMetricRecorder interface {
	RecordRejectedRequestMetrics(context.Context, awscatalog.Operation, awsapi.Request) error
}

func recordRequestError(ctx context.Context, service *Service, action string, input *awsapi.Request, failure *awswire.Error) *awswire.Error {
	// TODO: Comeback capture native pre-authentication and early transport rejection events before extending audit admission to those boundaries.
	if service.Model == nil {
		return failure
	}
	operation, known := service.Model.Operation(action)
	if !known {
		return failure
	}
	var err error
	if recorder, ok := service.Provider.(requestErrorRecorder); ok {
		decoded := awsapi.DecodedRequest{Operation: operation}
		if binder, ok := service.Provider.(requestErrorInputBinder); ok && input != nil {
			decoded.Input = binder.RequestErrorInput(operation, *input)
		}
		err = recorder.RecordRequestError(ctx, decoded, failure)
	}
	if err == nil {
		if recorder, ok := service.Provider.(requestErrorMetricRecorder); ok && input != nil {
			err = recorder.RecordRejectedRequestMetrics(ctx, operation, *input)
		}
	}
	if err != nil {
		return &awswire.Error{Code: "ServiceFailure", Message: "Unable to record authenticated API rejection", StatusCode: http.StatusInternalServerError}
	}
	return failure
}

func decodingError(ctx context.Context, service *Service, action string, input awsapi.Request, err error) *awswire.Error {
	if resolver, ok := service.Provider.(requestErrorResolver); ok {
		return resolver.ResolveRequestError(ctx, action, input, err)
	}
	if mapper, ok := service.Provider.(requestErrorMapper); ok {
		return mapper.RequestError(action, err)
	}
	protocol := service.Protocol
	if protocol == Query || protocol == EC2Query {
		return awswire.QueryInputError(protocol.modelProtocol(), err)
	}
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return &awswire.Error{Code: "UnknownOperationException", Message: "The requested operation is not recognized", StatusCode: http.StatusBadRequest}
	}
	if errors.Is(err, awsapi.ErrUnsupportedBinding) {
		return &awswire.Error{Code: "NotImplementedException", Message: "The modeled HTTP transport is not implemented", StatusCode: http.StatusNotImplemented}
	}
	var invalid *awsapi.ValidationError
	if errors.As(err, &invalid) {
		if protocol == RestJSON {
			return &awswire.Error{Code: "ValidationException", Message: invalid.Error(), StatusCode: http.StatusBadRequest}
		}
		return &awswire.Error{Code: "InvalidInputException", Message: invalid.Error(), StatusCode: http.StatusBadRequest, Reason: "INVALID_VALUE"}
	}
	return &awswire.Error{Code: "InternalFailure", Message: "Unable to bind the AWS request model", StatusCode: http.StatusInternalServerError}
}
