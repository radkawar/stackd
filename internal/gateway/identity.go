package gateway

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/identity"
)

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

// Authentication failure names belong to the target service's wire contract.
// KMS, Logs and Cognito use JSON exception names for invalid credentials.
func serviceAuthenticationError(service *Service, apiErr *awswire.Error) *awswire.Error {
	if service != nil && (service.SigningName == "kms" || service.SigningName == "logs" || service.SigningName == "cognito-idp") && apiErr.Code == "InvalidClientTokenId" {
		copy := *apiErr
		copy.Code = "UnrecognizedClientException"
		copy.StatusCode = http.StatusBadRequest
		copy.Message = "The security token included in the request is invalid"
		return &copy
	}
	if service != nil && service.SigningName == "cognito-idp" && apiErr.Code == "IncompleteSignature" {
		copy := *apiErr
		copy.Code = "IncompleteSignatureException"
		return &copy
	}
	return apiErr
}

// CredentialResolver resolves locally issued root, IAM and STS credentials.
type CredentialResolver interface {
	Resolve(context.Context, string) (identity.Credential, error)
}

type usageRecorder interface {
	RecordUsage(context.Context, string, string, string) error
}

type credentialScope struct {
	accessKey string
	date      string
	region    string
	service   string
}

func parseCredential(r *http.Request) (credentialScope, error) {
	var credential string
	if authorization := r.Header.Get("Authorization"); authorization != "" {
		if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") {
			return credentialScope{}, fmt.Errorf("only AWS4-HMAC-SHA256 authentication is supported")
		}
		for _, parameter := range strings.Split(strings.TrimPrefix(authorization, "AWS4-HMAC-SHA256 "), ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if ok && key == "Credential" {
				if credential != "" {
					return credentialScope{}, fmt.Errorf("duplicate Credential")
				}
				credential = value
			}
		}
	} else {
		credential = r.URL.Query().Get("X-Amz-Credential")
	}
	if credential == "" {
		return credentialScope{}, fmt.Errorf("AWS Signature Version 4 credentials are required")
	}
	parts := strings.Split(credential, "/")
	if len(parts) != 5 || parts[0] == "" || len(parts[1]) != 8 || parts[2] == "" || parts[3] == "" || parts[4] != "aws4_request" {
		return credentialScope{}, fmt.Errorf("invalid credential scope")
	}
	return credentialScope{accessKey: parts[0], date: parts[1], region: parts[2], service: parts[3]}, nil
}
