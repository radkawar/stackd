package sqs

import (
	"net/http"

	"stackd/internal/endpoints"
)

// EndpointRegion binds the generated regional service host to normal SQS
// protocol/authentication routing. Queue identity still comes from the native
// account/name owner and QueueUrl; no hostname-created queue registry exists.
func (s *Service) EndpointRegion(r *http.Request) (string, bool) {
	id, region, matched := endpoints.ResourceHost(r.Host, s.endpointDomain, "sqs")
	if id != "" {
		return "", matched
	}
	return region, matched
}
