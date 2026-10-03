package gateway

import (
	"net/http"

	"stackd/iam/policy"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// A service-owned native endpoint uses the same verified credentials, body
// bounds, region controls and observed transport as generated control APIs.
// Route selection conveys no authorization; the owner must check live resource
// identity and policies before forwarding native bytes.
type dataPlaneProvider interface {
	DataPlaneRegion(*http.Request) (string, bool)
	ServeDataPlane(http.ResponseWriter, *http.Request)
}

func (g *Gateway) serveDataPlane(w http.ResponseWriter, r *http.Request) bool {
	for i := range g.services {
		service := &g.services[i]
		provider, ok := service.Provider.(dataPlaneProvider)
		if !ok {
			continue
		}
		region, matched := provider.DataPlaneRegion(r)
		if !matched {
			continue
		}
		fail := func(e *awswire.Error) { awswire.RESTJSONError(w, r, service.Model, e) }
		partition := awscatalog.RegionPartition(region)
		if partition == "" {
			fail(&awswire.Error{Code: "ValidationException", Message: "Invalid native endpoint region.", StatusCode: 400})
			return true
		}
		if hasSigningMaterial(r.Header, r.URL.Query()) {
			authenticated, rejected := g.Authenticate(r, service.SigningName, region)
			if rejected != nil {
				fail(serviceAuthenticationError(service, rejected))
				return true
			}
			r = authenticated
			if rejected := g.checkRegion(r, service); rejected != nil {
				fail(rejected)
				return true
			}
		} else {
			metadata := awsctx.FromContext(r.Context())
			metadata.Region, metadata.Partition, metadata.AccountID = region, partition, policy.AnonymousAccountID
			BindRequestTransport(r, &metadata)
			r = r.WithContext(awsctx.WithMetadata(r.Context(), metadata))
		}
		r.Body = http.MaxBytesReader(w, r.Body, g.config.MaxBodyBytes)
		provider.ServeDataPlane(w, r)
		return true
	}
	return false
}
