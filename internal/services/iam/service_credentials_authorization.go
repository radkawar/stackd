package iam

import (
	"context"
	"strconv"
	"strings"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
)

func serviceCredentialAuthorizationResource(ctx context.Context, m awsctx.Metadata) (string, bool) {
	in, ok := awsapi.Input[iamapi.ListServiceSpecificCredentialsInput](ctx)
	if ok && in.AllUsers != nil && bool(*in.AllUsers) {
		return resourceARN(m, "user", "/", "*"), true
	}
	return "", false
}

func serviceCredentialAuthorizationContext(ctx context.Context, a *account) map[string][]string {
	decoded, _ := awsapi.FromContext(ctx)
	var id string
	switch in := decoded.Input.(type) {
	case *iamapi.CreateServiceSpecificCredentialInput:
		conditions := map[string][]string{"iam:ServiceSpecificCredentialServiceName": {strings.ToLower(inputString(in.ServiceName))}}
		if in.CredentialAgeDays != nil {
			conditions["iam:ServiceSpecificCredentialAgeDays"] = []string{strconv.FormatInt(int64(*in.CredentialAgeDays), 10)}
		}
		return conditions
	case *iamapi.UpdateServiceSpecificCredentialInput:
		id = inputString(in.ServiceSpecificCredentialId)
	case *iamapi.ResetServiceSpecificCredentialInput:
		id = inputString(in.ServiceSpecificCredentialId)
	case *iamapi.DeleteServiceSpecificCredentialInput:
		id = inputString(in.ServiceSpecificCredentialId)
	default:
		return nil
	}
	if record := a.serviceCredentials[id]; record != nil {
		return map[string][]string{"iam:ServiceSpecificCredentialServiceName": {record.ServiceName}}
	}
	return nil
}
