package iam

import (
	"context"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func listServiceSpecificCredentials(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ListServiceSpecificCredentialsInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	allUsers := in.AllUsers != nil && bool(*in.AllUsers)
	if allUsers && in.UserName != nil {
		return nil, invalidInput("Cannot list credentials for all users if a username is given")
	}
	service := ""
	if in.ServiceName != nil && *in.ServiceName != "" {
		service, _, apiErr = serviceCredentialService(inputString(in.ServiceName))
		if apiErr != nil {
			return nil, apiErr
		}
	}
	userID := ""
	if !allUsers {
		u, apiErr := loginUser(a, m, inputString(in.UserName))
		if apiErr != nil {
			return nil, apiErr
		}
		userID = u.UserId
	}
	users := make(map[string]*user, len(a.users))
	for _, u := range a.users {
		users[u.UserId] = u
	}
	items := make(iamapi.ServiceSpecificCredentialsListType, 0)
	now := a.currentTime
	for _, record := range a.serviceCredentials {
		if (!allUsers && record.UserID != userID) || (service != "" && record.ServiceName != service) {
			continue
		}
		if u := users[record.UserID]; u != nil {
			items = append(items, wireServiceCredentialMetadata(*record, u, now))
		}
	}
	items, pagination, apiErr := page(ctx, items, func(record iamapi.ServiceSpecificCredentialMetadata) string {
		return string(*record.ServiceSpecificCredentialId)
	}, m, in)
	if apiErr != nil {
		return nil, apiErr
	}
	return &iamapi.ListServiceSpecificCredentialsOutput{ServiceSpecificCredentials: items, IsTruncated: wirePointer(iamapi.BooleanType(pagination.IsTruncated)), Marker: wireMarker(pagination)}, nil
}
