package organizations

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"stackd/internal/awsapi"
	"stackd/internal/awswire"
)

// RequestError maps generated validation failures for both endpoint paths.
// AWS includes the violated constraint and member path in Organizations Reason.
func (*Service) RequestError(action string, err error) *awswire.Error {
	if errors.Is(err, awsapi.ErrUnknownOperation) {
		return failure("UnknownOperationException", "The requested operation is not recognized.")
	}
	var invalid *awsapi.ValidationError
	if !errors.As(err, &invalid) {
		return &awswire.Error{Code: "ServiceException", Message: "Unable to bind the Organizations request model.", StatusCode: http.StatusInternalServerError}
	}
	reason := "INVALID_VALUE"
	switch invalid.Constraint {
	case "required":
		reason = "INPUT_REQUIRED"
	case "pattern":
		reason = "INVALID_PATTERN"
	case "length.min":
		reason = "MIN_LENGTH_EXCEEDED"
	case "length.max":
		reason = "MAX_LENGTH_EXCEEDED"
	case "range.min":
		reason = "MIN_VALUE_EXCEEDED"
	case "range.max":
		reason = "MAX_VALUE_EXCEEDED"
	}
	if reason != "INVALID_VALUE" {
		reason += ":" + requestMemberPath(invalid.Path)
	}
	if action == "InviteAccountToOrganization" {
		switch invalid.Path {
		case "Target":
			reason = "INVALID_PATTERN"
		case "Target.Type":
			reason = "INVALID_PARTY_TYPE_TARGET"
		case "Target.Id":
			if invalid.Constraint == "required" {
				reason = "INVALID_PARTY_TYPE_TARGET"
			}
		}
	}
	if (action == "DescribeEffectivePolicy" || action == "ListEffectivePolicyValidationErrors") && invalid.Path == "PolicyType" && invalid.Constraint == "enum" {
		reason = "INVALID_ENUM:POLICY_TYPE"
		if invalid.EnumValue == "SERVICE_CONTROL_POLICY" || action == "ListEffectivePolicyValidationErrors" {
			reason = "INVALID_ENUM_POLICY_TYPE"
		}
	}
	if action == "ListEffectivePolicyValidationErrors" && invalid.Path == "AccountId" {
		reason = "TARGET_NOT_SUPPORTED"
	}
	if invalid.Path == "Filter.ActionType" {
		reason = "INVALID_ENUM:FILTER_ACTION_TYPE"
	}
	return &awswire.Error{Code: "InvalidInputException", Message: invalid.Error(), Reason: reason, StatusCode: http.StatusBadRequest}
}

var memberIndex = regexp.MustCompile(`\[(\d+)\]`)
var memberWord = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func requestMemberPath(path string) string {
	path = memberIndex.ReplaceAllStringFunc(path, func(index string) string {
		n, _ := strconv.Atoi(index[1 : len(index)-1])
		return "_" + strconv.Itoa(n+1) + "_member"
	})
	path = memberWord.ReplaceAllString(path, "${1}_${2}")
	return strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}
