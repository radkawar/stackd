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
	}
	return nil, "", false
}
