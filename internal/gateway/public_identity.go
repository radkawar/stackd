package gateway

import (
	"net/http"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// SSO's public REST operations authenticate client secrets or bearer tokens in
// their service owner. The model, not the URL alone, decides which commands can
// bypass SigV4. CreateTokenWithIAM and malformed signatures never take this path.
func (g *Gateway) servePublicIdentityREST(w http.ResponseWriter, r *http.Request) bool {
	if hasSigningMaterial(r.Header, r.URL.Query()) {
		return false
	}
	var service *Service
	for i := range g.services {
		candidate := &g.services[i]
		if (candidate.Name != "ssooidc" && candidate.Name != "sso") || candidate.Protocol != RestJSON || candidate.Model == nil {
			continue
		}
		operation, _, matched := candidate.Model.MatchHTTPOperation(r.Method, r.URL.EscapedPath(), r.URL.Query(), r.Header)
		if !matched || !operation.OptionalAuth || len(operation.AuthSchemes) != 0 {
			continue
		}
		if service != nil {
			awswire.RESTJSONError(w, r, candidate.Model, &awswire.Error{Code: "InvalidRequestException", Message: "Ambiguous identity operation.", StatusCode: 400})
			return true
		}
		service = candidate
	}
	if service == nil {
		return false
	}
	metadata := awsctx.FromContext(r.Context())
	metadata.Region = g.config.UnsignedRegion
	if region := identityEndpointRegion(r.Host, "oidc", "oidc-fips", "portal.sso", "portal.sso-fips"); region != "" {
		metadata.Region = region
	}
	metadata.Partition = awscatalog.RegionPartition(metadata.Region)
	BindRequestTransport(r, &metadata)
	r = r.WithContext(awsctx.WithMetadata(r.Context(), metadata))
	g.serveOperation(w, r, service, func(e *awswire.Error) { awswire.RESTJSONError(w, r, service.Model, e) })
	return true
}
