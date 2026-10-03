package gateway

import (
	"net"
	"net/http"
	"slices"
	"strings"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// servePublicJSON admits only Cognito user/identity-pool operations whose
// generated model leaves authentication to service-owned token authority.
// Administrative operations retain signature verification.
func (g *Gateway) servePublicJSON(w http.ResponseWriter, r *http.Request) bool {
	prefix, action, ok := awswire.JSONTarget(r.Header.Get("X-Amz-Target"))
	if !ok {
		return false
	}
	var service *Service
	for i := range g.services {
		candidate := &g.services[i]
		if (candidate.Name == "cognitoidp" || candidate.Name == "cognitoidentity") && candidate.TargetPrefix == prefix && candidate.Protocol == JSON11 && candidate.Model != nil {
			service = candidate
			break
		}
	}
	if service == nil {
		return false
	}
	writeError := func(failure *awswire.Error) {
		awswire.JSONError(w, r, failure)
	}
	if len(r.Header.Values("X-Amz-Target")) != 1 {
		writeError(&awswire.Error{Code: "UnknownOperationException", Message: "Expected one operation target", StatusCode: http.StatusBadRequest})
		return true
	}
	operation, known := service.Model.Operation(action)
	if !known {
		writeError(&awswire.Error{Code: "UnknownOperationException", Message: "Unknown operation", StatusCode: http.StatusBadRequest})
		return true
	}
	if !operation.OptionalAuth || len(operation.AuthSchemes) != 0 {
		if hasSigningMaterial(r.Header, r.URL.Query()) {
			return false
		}
		writeError(&awswire.Error{Code: "MissingAuthenticationTokenException", Message: "Missing Authentication Token", StatusCode: http.StatusBadRequest})
		return true
	}
	if !slices.Contains(service.Provider.Operations(), action) {
		writeError(&awswire.Error{Code: "UnknownOperationException", Message: "Operation is not implemented", StatusCode: http.StatusBadRequest})
		return true
	}
	selected, failure := selectProtocol(r, service)
	if failure != nil {
		writeError(failure)
		return true
	}
	// Never synthesize an account or IAM principal for public application calls.
	// The provider resolves the real pool scope from its client/token authority.
	metadata := awsctx.FromContext(r.Context())
	metadata.Region = g.config.UnsignedRegion
	if region := cognitoEndpointRegion(r.Host); region != "" {
		metadata.Region = region
	}
	metadata.Partition = awscatalog.RegionPartition(metadata.Region)
	BindRequestTransport(r, &metadata)
	r = r.WithContext(awsctx.WithMetadata(r.Context(), metadata))
	g.serveOperation(w, r, selected, writeError)
	return true
}

// cognitoEndpointRegion trusts only an SDK-described region on a matching AWS
// partition endpoint. Custom endpoint overrides use the configured local region.
func cognitoEndpointRegion(host string) string {
	return identityEndpointRegion(host, "cognito-idp", "cognito-idp-fips", "cognito-identity", "cognito-identity-fips")
}

func identityEndpointRegion(host string, prefixes ...string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	var endpoint string
	for _, prefix := range prefixes {
		if rest, ok := strings.CutPrefix(host, prefix+"."); ok {
			endpoint = rest
			break
		}
	}
	if endpoint == "" {
		return ""
	}
	region, suffix, ok := strings.Cut(endpoint, ".")
	if !ok {
		return ""
	}
	var standard, dualstack string
	switch awscatalog.RegionPartition(region) {
	case "aws", "aws-us-gov":
		standard, dualstack = "amazonaws.com", "api.aws"
	case "aws-cn":
		standard, dualstack = "amazonaws.com.cn", "api.amazonwebservices.com.cn"
	case "aws-eusc":
		standard, dualstack = "amazonaws.eu", "api.amazonwebservices.eu"
	case "aws-iso":
		standard, dualstack = "c2s.ic.gov", "api.aws.ic.gov"
	case "aws-iso-b":
		standard, dualstack = "sc2s.sgov.gov", "api.aws.scloud"
	case "aws-iso-e":
		standard, dualstack = "cloud.adc-e.uk", "api.cloud-aws.adc-e.uk"
	case "aws-iso-f":
		standard, dualstack = "csp.hci.ic.gov", "api.aws.hci.ic.gov"
	default:
		return ""
	}
	if suffix != standard && suffix != dualstack {
		return ""
	}
	return region
}

// JWKS paths identify a regional pool. Local endpoint overrides use that pool's
// region; a recognized native hostname retains its own endpoint region.
func (g *Gateway) serveCognitoDiscovery(w http.ResponseWriter, r *http.Request) bool {
	poolID, path, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !ok || path != ".well-known/jwks.json" {
		return false
	}
	region, suffix, ok := strings.Cut(poolID, "_")
	if !ok || suffix == "" || awscatalog.RegionPartition(region) == "" {
		return false
	}
	for _, service := range g.services {
		if service.Name != "cognitoidp" {
			continue
		}
		discovery, ok := service.Provider.(interface {
			ServeDiscovery(http.ResponseWriter, *http.Request)
		})
		if !ok {
			return false
		}
		if endpoint := cognitoEndpointRegion(r.Host); endpoint != "" {
			region = endpoint
		}
		metadata := awsctx.FromContext(r.Context())
		metadata.Region, metadata.Partition = region, awscatalog.RegionPartition(region)
		BindRequestTransport(r, &metadata)
		discovery.ServeDiscovery(w, r.WithContext(awsctx.WithMetadata(r.Context(), metadata)))
		return true
	}
	return false
}
