package apievents

import (
	"strings"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Projection is a service's native audit contract. Classification and response
// presence are independent: STS AssumeRole, for example, is read-only but logs a
// response. Smithy owns shape encoding, not those behavioral decisions.
type Projection struct {
	EventName string
	Category  journal.APICallCategory
	ReadOnly  bool
	Request   awsapi.DocumentProjection
	Response  *awsapi.DocumentProjection
}

// Call builds public parameters from generated DTOs. Sources add resource
// identities and operation-specific native fields, then Record in the command's
// transaction. A nil Response omits the API output, including credential material
// and data-plane payloads, before serialization.
func (p Projection) Call(model awscatalog.Service, operation awscatalog.Operation, input, output any, failure *awswire.Error) (journal.APICallCompleted, error) {
	call := journal.APICallCompleted{EventSource: model.CloudTrailEventSource, EventName: p.EventName, Category: p.Category, ReadOnly: p.ReadOnly}
	if call.EventName == "" {
		call.EventName = string(operation.Name)
	}
	var err error
	call.RequestParameters, err = awsapi.EncodeDocument(model, operation.Input, input, &p.Request)
	if err != nil {
		return call, err
	}
	if failure != nil {
		call.ErrorCode = ErrorName(model, operation, failure.Code)
		call.ErrorMessage = failure.Message
	} else if p.Response != nil {
		call.ResponseElements, err = awsapi.EncodeDocument(model, operation.Output, output, p.Response)
	}
	return call, err
}

// ErrorName resolves protocol-specific error codes to their modeled names, as
// observed in IAM and SQS audit records. Native exceptions remain service-owned.
func ErrorName(model awscatalog.Service, operation awscatalog.Operation, code string) string {
	for _, id := range operation.Errors {
		shape, _ := model.Shape(id)
		if shape.Error.Code == code {
			_, name, _ := strings.Cut(string(id), "#")
			return name
		}
	}
	return code
}
