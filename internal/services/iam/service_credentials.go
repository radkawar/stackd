package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

var serviceCredentialNamePattern = regexp.MustCompile(`^[a-zA-Z0-9.-]*$`)

func serviceCredentialService(name string) (canonical string, apiKey bool, err *awswire.Error) {
	if !serviceCredentialNamePattern.MatchString(name) {
		return "", false, invalid("ServiceName must match [a-zA-Z0-9.-]*.")
	}
	canonical = strings.ToLower(name)
	switch canonical {
	case "codecommit.amazonaws.com", "cassandra.amazonaws.com":
		return canonical, false, nil
	case "bedrock.amazonaws.com", "logs.amazonaws.com", "cloudwatch.amazonaws.com", "aws-external-anthropic.amazonaws.com":
		return canonical, true, nil
	default:
		return "", false, &awswire.Error{Code: "NoSuchEntity", Message: "No such service " + name + " is supported for Service Specific Credentials", StatusCode: 404}
	}
}

func createServiceSpecificCredential(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.CreateServiceSpecificCredentialInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	service, apiKey, apiErr := serviceCredentialService(inputString(in.ServiceName))
	if apiErr != nil {
		return nil, apiErr
	}
	u, apiErr := loginUser(a, m, inputString(in.UserName))
	if apiErr != nil {
		return nil, apiErr
	}
	count := 0
	for _, record := range a.serviceCredentials {
		if record.UserID == u.UserId && record.ServiceName == service {
			count++
		}
	}
	if count >= 2 {
		return nil, limit("Cannot exceed quota for ServiceSpecificCredentialsPerUser: 2")
	}
	alias, slot := availableServiceCredentialAlias(a, service, u.UserName, m.AccountID)
	now := a.currentTime.Truncate(time.Millisecond)
	record := &ServiceCredentialRecord{ID: newID("ACCA"), UserID: u.UserId, ServiceName: service, Status: "Active", CreateDate: now, Slot: slot}
	if in.CredentialAgeDays != nil {
		record.CredentialAgeDays = int64(*in.CredentialAgeDays)
		expires := now.Add(time.Duration(record.CredentialAgeDays) * 24 * time.Hour)
		record.ExpirationDate = &expires
	}
	if apiKey {
		record.ServiceCredentialAlias = alias
	} else {
		record.ServiceUserName = alias
	}
	secret, apiErr := newServiceCredentialSecret(*record)
	if apiErr != nil {
		return nil, apiErr
	}
	record.SecretDigest = sha256.Sum256([]byte(secret))
	a.serviceCredentials[record.ID] = record
	return &iamapi.CreateServiceSpecificCredentialOutput{ServiceSpecificCredential: wireServiceCredential(*record, u, secret, a.currentTime)}, nil
}

func availableServiceCredentialAlias(a *account, service, userName, accountID string) (string, int) {
	for slot := 0; ; slot++ {
		alias := userName
		if slot > 0 {
			alias += "+" + strconv.Itoa(slot)
		}
		alias += "-at-" + accountID
		used := false
		for _, record := range a.serviceCredentials {
			if record.ServiceName == service && (record.ServiceUserName == alias || record.ServiceCredentialAlias == alias) {
				used = true
				break
			}
		}
		if !used {
			return alias, slot
		}
	}
}

func newServiceCredentialSecret(record ServiceCredentialRecord) (string, *awswire.Error) {
	// Unlike human passwords, these secrets carry 360 bits of generated entropy;
	// a SHA-256 digest suffices without a password-stretching work factor.
	bytes := make([]byte, 45)
	if _, err := rand.Read(bytes); err != nil {
		return "", &awswire.Error{Code: "ServiceFailure", Message: "Unable to generate service-specific credentials.", StatusCode: 500}
	}
	secret := base64.StdEncoding.EncodeToString(bytes)
	if record.ServiceCredentialAlias != "" {
		secret = serviceCredentialTokenPrefix(record.ServiceName) + base64.StdEncoding.EncodeToString([]byte(record.ServiceCredentialAlias+":"+secret))
	}
	return secret, nil
}

func serviceCredentialTokenPrefix(service string) string {
	switch service {
	case "bedrock.amazonaws.com":
		return "ABSK"
	case "logs.amazonaws.com":
		return "ACWL"
	case "cloudwatch.amazonaws.com":
		return "APIAACWM"
	case "aws-external-anthropic.amazonaws.com":
		return "AEAA"
	default:
		return ""
	}
}
