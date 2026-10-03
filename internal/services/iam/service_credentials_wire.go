package iam

import (
	"time"

	iamapi "stackd/internal/awsapi/iam"
)

func serviceCredentialStatus(record ServiceCredentialRecord, now time.Time) string {
	if record.ExpirationDate != nil && !now.Before(*record.ExpirationDate) {
		return "Expired"
	}
	return record.Status
}

func wireServiceCredential(record ServiceCredentialRecord, u *user, secret string, now time.Time) *iamapi.ServiceSpecificCredential {
	result := &iamapi.ServiceSpecificCredential{
		CreateDate: wirePointer(record.CreateDate), ExpirationDate: record.ExpirationDate,
		ServiceName: wirePointer(iamapi.ServiceName(record.ServiceName)), ServiceSpecificCredentialId: wirePointer(iamapi.ServiceSpecificCredentialId(record.ID)),
		Status: wirePointer(iamapi.StatusType(serviceCredentialStatus(record, now))), UserName: wirePointer(iamapi.UserNameType(u.UserName)),
	}
	if record.ServiceCredentialAlias != "" {
		result.ServiceCredentialAlias = wirePointer(iamapi.ServiceCredentialAlias(record.ServiceCredentialAlias))
		result.ServiceCredentialSecret = wirePointer(iamapi.ServiceCredentialSecret(secret))
	} else {
		result.ServiceUserName = wirePointer(iamapi.ServiceUserName(record.ServiceUserName))
		result.ServicePassword = wirePointer(iamapi.ServicePassword(secret))
	}
	return result
}

func wireServiceCredentialMetadata(record ServiceCredentialRecord, u *user, now time.Time) iamapi.ServiceSpecificCredentialMetadata {
	result := iamapi.ServiceSpecificCredentialMetadata{
		CreateDate: wirePointer(record.CreateDate), ExpirationDate: record.ExpirationDate,
		ServiceName: wirePointer(iamapi.ServiceName(record.ServiceName)), ServiceSpecificCredentialId: wirePointer(iamapi.ServiceSpecificCredentialId(record.ID)),
		Status: wirePointer(iamapi.StatusType(serviceCredentialStatus(record, now))), UserName: wirePointer(iamapi.UserNameType(u.UserName)),
	}
	if record.ServiceCredentialAlias != "" {
		result.ServiceCredentialAlias = wirePointer(iamapi.ServiceCredentialAlias(record.ServiceCredentialAlias))
	} else {
		result.ServiceUserName = wirePointer(iamapi.ServiceUserName(record.ServiceUserName))
	}
	return result
}
