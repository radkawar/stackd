package gateway

import "net/http"

// endpointRegionProvider owns a configured regional service hostname. Resource
// authorization stays in its protocol provider after unchanged-byte SigV4.
type endpointRegionProvider interface {
	EndpointRegion(*http.Request) (string, bool)
}

func (g *Gateway) resourceEndpoint(r *http.Request) (*Service, string, bool) {
	for i := range g.services {
		service := &g.services[i]
		if owner, ok := service.Provider.(endpointRegionProvider); ok {
			if region, matched := owner.EndpointRegion(r); matched {
				return service, region, true
			}
		}
		// Separately specified native protocols own their paths before
		// anonymous S3 dispatch. Selection is not authentication: the ordinary
		// signer checks below still verify this service and the selected region.
		if owner, ok := service.Provider.(privateOperationProvider); ok {
			if _, matched := owner.PrivateOperation(r); matched {
				scope, _ := parseCredential(r)
				return service, scope.region, true
			}
		}
	}
	return nil, "", false
}
