package awswire

import (
	"errors"
	"net/http"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
)

// QueryInputError maps generated Query decoding failures to wire errors.
// Primitive parsing precedes modeled validation and has a distinct AWS error.
func QueryInputError(protocol awscatalog.Protocol, err error) *Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return &Error{Code: "InvalidAction", Message: "The requested operation is not recognized", StatusCode: http.StatusBadRequest}
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) {
		code := "ValidationError"
		if protocol == awscatalog.EC2Query {
			code = "InvalidParameterValue"
			if validation.Constraint == "query.unknown" {
				return &Error{Code: "UnknownParameter", Message: "The parameter " + validation.Path + " is not recognized", StatusCode: http.StatusBadRequest}
			}
			if validation.Constraint == "required" {
				code = "MissingParameter"
			}
			return &Error{Code: code, Message: validation.Error(), StatusCode: http.StatusBadRequest}
		}
		if validation.Constraint == "query" {
			code = "MalformedInput"
		}
		return &Error{Code: code, Message: validation.Error(), StatusCode: http.StatusBadRequest}
	}
	return &Error{Code: "InternalFailure", Message: "Unable to bind the AWS request model", StatusCode: http.StatusInternalServerError}
}
