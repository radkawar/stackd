package iam

import (
	"errors"
	"net/http"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// RequestError maps generated input failures to IAM's wire error contract.
// Both the gateway and standalone service use it before invoking a handler.
func (*Service) RequestError(action string, err error) *awswire.Error {
	apiErr := awswire.QueryInputError(awscatalog.AWSQuery, err)
	if apiErr.StatusCode == http.StatusInternalServerError {
		return requestBindingFailure()
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) {
		if (action == "CreateRole" || action == "UpdateRole") && validation.Path == "MaxSessionDuration" && validation.Constraint == "range.min" {
			apiErr.Code = "ParamValidation"
		}
	}
	return apiErr
}
