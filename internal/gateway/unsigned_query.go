package gateway

import (
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Authentication material never falls back to anonymous routing. Include legacy
// signing fields and empty values so malformed or partial signatures fail closed.
func hasSigningMaterial(headers http.Header, params url.Values) bool {
	for key := range headers {
		if signingParameter(key) {
			return true
		}
	}
	for key := range params {
		if signingParameter(key) {
			return true
		}
	}
	return false
}

func signingParameter(key string) bool {
	switch strings.ToLower(key) {
	case "authorization", "x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-expires", "x-amz-security-token", "x-amz-signature", "x-amz-signedheaders", "awsaccesskeyid", "signature", "signatureversion", "signaturemethod", "securitytoken", "timestamp":
		return true
	}
	return false
}

func (g *Gateway) serveUnsignedQuery(w http.ResponseWriter, r *http.Request) {
	var service *Service
	writeError := func(apiErr *awswire.Error) {
		namespace := ""
		if service != nil {
			namespace = service.Namespace
		}
		awswire.QueryError(w, r, namespace, apiErr)
	}
	rejectAuth := func() {
		writeError(&awswire.Error{Code: "IncompleteSignature", Message: "AWS Signature Version 4 credentials are required", StatusCode: http.StatusBadRequest})
	}
	if r.URL.Path != "/" || len(r.Header.Values("X-Amz-Target")) != 0 {
		rejectAuth()
		return
	}
	if r.Method == http.MethodPost {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 {
			rejectAuth()
			return
		}
	} else if r.Method != http.MethodGet || (r.ContentLength != 0 && r.Body != nil) {
		rejectAuth()
		return
	}
	params, err := awswire.ParseQuery(r, awscatalog.AWSQuery)
	if err != nil {
		writeError(&awswire.Error{Code: "InvalidParameterValue", Message: err.Error(), StatusCode: http.StatusBadRequest})
		return
	}
	if hasSigningMaterial(nil, params) {
		rejectAuth()
		return
	}
	action := params.Get("Action")
	var name string
	switch action {
	case "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML":
		name = "sts"
	case "ConfirmSubscription", "Unsubscribe":
		name = "sns"
	default:
		rejectAuth()
		return
	}
	for i := range g.services {
		candidate := &g.services[i]
		if candidate.Name == name && candidate.SigningName == name && candidate.Protocol == Query {
			service = candidate
			break
		}
	}
	model, _ := awscatalog.LookupService(name)
	operation, exists := model.Operation(action)
	if service == nil || !exists || !slices.Contains(service.Provider.Operations(), action) {
		rejectAuth()
		return
	}
	// STS models optional authentication explicitly. SNS's published operation
	// documentation permits token confirmation and unprotected unsubscribe,
	// but its Smithy model omits optionalAuth. Only those two named commands
	// reach their service-owned authorization boundary without SigV4.
	if name == "sts" && (!operation.OptionalAuth || len(operation.AuthSchemes) != 0) {
		rejectAuth()
		return
	}
	if name == "sns" && !params.Has("Version") {
		// Native confirmation/cancellation links omit the Query API version.
		// The parsed form is shared with the ordinary generated decoder.
		params.Set("Version", service.QueryVersion)
	}
	metadata := awsctx.FromContext(r.Context())
	metadata.Region = g.config.UnsignedRegion
	if name == "sns" {
		metadata.Partition = awscatalog.RegionPartition(metadata.Region)
	}
	BindRequestTransport(r, &metadata)
	r = r.WithContext(awsctx.WithMetadata(r.Context(), metadata))
	g.serveOperation(w, r, service, writeError)
}
