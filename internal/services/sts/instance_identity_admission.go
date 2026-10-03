package sts

import (
	"context"
	"net/http"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// AdmitRequest rejects intrinsic credentials before ordinary STS input and IAM
// policy evaluation. Native STS accepts them for GetCallerIdentity only; unlike
// attached-profile sessions, GetSessionToken returns InvalidClientTokenId.
func (*Service) AdmitRequest(ctx context.Context, action string) *awswire.Error {
	if awsctx.FromContext(ctx).SessionType == string(identity.SessionTypeEC2InstanceIdentity) && action != "GetCallerIdentity" {
		return &awswire.Error{Code: "InvalidClientTokenId", Message: "The security token included in the request is invalid", StatusCode: http.StatusForbidden}
	}
	return nil
}
