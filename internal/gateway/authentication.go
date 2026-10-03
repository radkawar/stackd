package gateway

import (
	"errors"
	"net/http"
	"time"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// Authenticate verifies a signed request against a service-owned endpoint scope.
// The caller bounds the body and supplies its request ID before authentication.
// The bounded body is consumed before credential resolution can wait on storage.
// Verification uses the original host, path and query, restores the body, and
// retains authenticated runtime causality. Authorization belongs to the service.
func (g *Gateway) Authenticate(r *http.Request, signingName, region string) (*http.Request, *awswire.Error) {
	scope, err := parseCredential(r)
	if err != nil {
		return nil, &awswire.Error{Code: "IncompleteSignature", Message: err.Error(), StatusCode: http.StatusBadRequest}
	}
	if scope.service != signingName || scope.region != region {
		return nil, &awswire.Error{Code: "SignatureDoesNotMatch", Message: "Credential scope does not match the requested endpoint", StatusCode: http.StatusForbidden}
	}
	return g.authenticate(r, scope, nil)
}

// AuthenticateEKS verifies an EKS Kubernetes token's presigned STS identity with
// the native authenticator's 15-minute lifetime. The EKS owner validates the
// bounded token URL, supplies its endpoint signing region (not cluster region),
// and sets the expected signed x-k8s-aws-id cluster binding.
// Ordinary Authenticate retains the URL's exact X-Amz-Expires lifetime.
func (g *Gateway) AuthenticateEKS(r *http.Request, region string) (*http.Request, *awswire.Error) {
	scope, err := parseCredential(r)
	if err != nil || scope.service != "sts" || scope.region != region || r.Header.Get("Authorization") != "" || r.Header.Get("x-k8s-aws-id") == "" {
		return nil, &awswire.Error{Code: "InvalidClientTokenId", Message: "Invalid Kubernetes token identity", StatusCode: http.StatusForbidden}
	}
	return g.authenticatePolicy(r, scope, nil, true)
}

func (g *Gateway) authenticate(r *http.Request, scope credentialScope, model *awscatalog.Service) (*http.Request, *awswire.Error) {
	return g.authenticatePolicy(r, scope, model, false)
}

func (g *Gateway) authenticatePolicy(r *http.Request, scope credentialScope, model *awscatalog.Service, eksToken bool) (*http.Request, *awswire.Error) {
	body, wire := readSignatureBody(r)
	if wire != nil {
		return nil, wire
	}
	credential, err := g.config.Credentials.Resolve(r.Context(), scope.accessKey)
	if err != nil {
		code := "InvalidClientTokenId"
		if errors.Is(err, identity.ErrExpired) {
			code = "ExpiredToken"
		}
		return nil, &awswire.Error{Code: code, Message: "The local security token is invalid or expired", StatusCode: http.StatusForbidden}
	}
	metadata, err := identity.RequestMetadata(credential, scope.accessKey, scope.region, awsctx.FromContext(r.Context()).RequestID)
	if err != nil {
		return nil, &awswire.Error{Code: "InvalidClientTokenId", Message: err.Error(), StatusCode: http.StatusForbidden}
	}
	BindRequestTransport(r, &metadata)
	metadata.SignatureVersion, metadata.AuthenticationMethod = "SigV4", "AuthHeader"
	if r.Header.Get("Authorization") == "" {
		metadata.AuthenticationMethod = "QueryString"
	}
	r = r.WithContext(awsctx.WithMetadata(r.Context(), metadata))
	unsignedPayload := false
	if model != nil && r.Header.Get("X-Amz-Content-Sha256") == "UNSIGNED-PAYLOAD" {
		operation, _, matched := model.MatchHTTPOperation(r.Method, r.URL.EscapedPath(), r.URL.Query(), r.Header)
		unsignedPayload = matched && operation.UnsignedPayload
	}
	// SDK signatures use wall time; the resolver owns service-time token expiry.
	if wire := verifySignaturePolicy(r, body, scope, credential, time.Now(), unsignedPayload, eksToken); wire != nil {
		return nil, wire
	}
	if credential.SessionType == identity.SessionTypeEC2InstanceIdentity && scope.service != "sts" {
		// TODO: Comeback implement the documented Instance Connect, GuardDuty,
		// SSM, Lambda Managed Instances and AgentCore intrinsic consumers in
		// their service admission owners, not through ordinary IAM grants.
		code := "InvalidClientTokenId"
		if scope.service == "sqs" {
			code = "UnrecognizedClientException"
		}
		return nil, &awswire.Error{Code: code, Message: "The security token included in the request is invalid", StatusCode: http.StatusForbidden}
	}
	parent := credential.RequestParentEventID
	if g.config.Origin != nil {
		if invocation := g.config.Origin.InvocationParent(scope.accessKey); invocation != "" {
			parent = invocation
		}
	}
	if parent != "" {
		metadata.ParentEventID = parent
		r = r.WithContext(awsctx.WithMetadata(r.Context(), metadata))
	}
	return r, nil
}

// BindRequestTransport attaches actual connection properties to a caller's
// identity. Forwarded headers do not establish IAM source IP or TLS conditions.
func BindRequestTransport(r *http.Request, metadata *awsctx.Metadata) {
	metadata.TransportKnown = true
	metadata.SourceIP = remoteIP(r.RemoteAddr)
	metadata.SecureTransport = r.TLS != nil
	metadata.UserAgent = r.UserAgent()
	metadata.TraceHeader = r.Header.Get("X-Amzn-Trace-Id")
}
