package gateway

import (
	"net/http"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// VerifyS3PresignedRequest verifies an S3-style URL against the service-owned
// credential and region, not the IAM credential resolver. The normal gateway
// and private service downloads share the canonical request implementation.
func VerifyS3PresignedRequest(r *http.Request, credential identity.Credential, region string, now time.Time) *awswire.Error {
	scope, err := parseCredential(r)
	if err != nil || r.Header.Get("Authorization") != "" || scope.accessKey != credential.AccessKeyID || scope.region != region || scope.service != "s3" {
		return &awswire.Error{Code: "AccessDenied", Message: "Access Denied", StatusCode: http.StatusForbidden}
	}
	return verifySignature(r, scope, credential, now, false)
}

// VerifyS3SignedRequest verifies a header-signed S3 request against an explicit
// service-owned credential. It never resolves IAM identity or grants access to
// a resource. The caller must bound the body before calling, then authorize the
// decoded operation through S3. Successful verification replaces aws-chunked
// framing with validated object bytes and exposes verified checksum trailers.
func VerifyS3SignedRequest(r *http.Request, credential identity.Credential, region string, now time.Time) *awswire.Error {
	scope, err := parseCredential(r)
	if err != nil || r.Header.Get("Authorization") == "" || scope.accessKey != credential.AccessKeyID || scope.region != region || scope.service != "s3" {
		return &awswire.Error{Code: "AccessDenied", Message: "Access Denied", StatusCode: http.StatusForbidden}
	}
	if rejected := validateS3Authentication(r); rejected != nil {
		return rejected
	}
	return verifySignature(r, scope, credential, now, false)
}
