package iam

import (
	"context"
	"crypto/sha256"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func findServiceCredential(a *account, m awsctx.Metadata, username, id string) (*user, *ServiceCredentialRecord, *awswire.Error) {
	u, apiErr := loginUser(a, m, username)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	record := a.serviceCredentials[id]
	if record == nil {
		return nil, nil, missing("service specific credential", id)
	}
	if record.UserID != u.UserId {
		return nil, nil, invalid("User " + u.UserName + " does not have a service specific credential with id " + id)
	}
	return u, record, nil
}

func resetServiceSpecificCredential(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ResetServiceSpecificCredentialInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	u, record, apiErr := findServiceCredential(a, m, inputString(in.UserName), inputString(in.ServiceSpecificCredentialId))
	if apiErr != nil {
		return nil, apiErr
	}
	if serviceCredentialStatus(*record, a.currentTime) == "Expired" {
		return nil, invalidInput("Cannot reset an expired service specific credential.")
	}
	secret, apiErr := newServiceCredentialSecret(*record)
	if apiErr != nil {
		return nil, apiErr
	}
	record.SecretDigest = sha256.Sum256([]byte(secret))
	return &iamapi.ResetServiceSpecificCredentialOutput{ServiceSpecificCredential: wireServiceCredential(*record, u, secret, a.currentTime)}, nil
}

func updateServiceSpecificCredential(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.UpdateServiceSpecificCredentialInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	_, record, apiErr := findServiceCredential(a, m, inputString(in.UserName), inputString(in.ServiceSpecificCredentialId))
	if apiErr != nil {
		return nil, apiErr
	}
	status := inputString(in.Status)
	if status != "Active" && status != "Inactive" {
		return nil, invalidInput("Operation does not support status " + status)
	}
	if serviceCredentialStatus(*record, a.currentTime) == "Expired" {
		return nil, invalidInput("Cannot update an expired service specific credential.")
	}
	record.Status = status
	return &iamapi.UpdateServiceSpecificCredentialOutput{}, nil
}

func deleteServiceSpecificCredential(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.DeleteServiceSpecificCredentialInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	_, record, apiErr := findServiceCredential(a, m, inputString(in.UserName), inputString(in.ServiceSpecificCredentialId))
	if apiErr != nil {
		return nil, apiErr
	}
	delete(a.serviceCredentials, record.ID)
	return &iamapi.DeleteServiceSpecificCredentialOutput{}, nil
}
