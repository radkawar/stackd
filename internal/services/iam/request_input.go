package iam

import (
	"context"

	"stackd/internal/awsapi"
	"stackd/internal/awswire"
)

// generatedIAMInput reads the request validated by the gateway or ServeHTTP.
func generatedIAMInput[T any](ctx context.Context) (*T, *awswire.Error) {
	input, ok := awsapi.Input[T](ctx)
	if !ok {
		return nil, requestBindingFailure()
	}
	return input, nil
}

func inputString[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

func requestBindingFailure() *awswire.Error {
	return &awswire.Error{Code: "ServiceFailure", Message: "IAM request binding failed.", StatusCode: 500}
}
