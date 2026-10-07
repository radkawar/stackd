package gateway

import (
	"mime"
	"net"
	"net/http"
	"strings"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

// Hosted authorization shares the S3 listener. Only OAuth-shaped requests bypass
// SigV4; client credentials, upstream state and tokens remain service authority.
func (g *Gateway) serveCognitoOAuth(w http.ResponseWriter, r *http.Request) bool {
	if len(r.Header.Values("X-Amz-Target")) != 0 {
		return false
	}
	query := r.URL.Query()
	switch r.URL.Path {
	case "/oauth2/authorize":
		if r.Method != http.MethodGet || (!query.Has("client_id") && !query.Has("response_type")) {
			return false
		}
	case "/oauth2/idpresponse":
		if r.Method == http.MethodGet {
			if !query.Has("state") || (!query.Has("code") && !query.Has("error")) {
				return false
			}
		} else if r.Method != http.MethodPost {
			return false
		}
	case "/oauth2/token":
		if r.Method != http.MethodPost {
			return false
		}
	default:
		return false
	}
	if r.Method == http.MethodPost {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 {
			return false
		}
	}
	for key, values := range r.Header {
		if !signingParameter(key) {
			continue
		}
		if !strings.EqualFold(key, "Authorization") || r.URL.Path != "/oauth2/token" || len(values) != 1 || !strings.HasPrefix(values[0], "Basic ") {
			return false
		}
	}
	for key := range query {
		if signingParameter(key) {
			return false
		}
	}
	for _, service := range g.services {
		if service.Name != "cognitoidp" {
			continue
		}
		hosted, ok := service.Provider.(interface {
			ServeOAuth(http.ResponseWriter, *http.Request)
		})
		if !ok {
			return false
		}
		metadata := awsctx.FromContext(r.Context())
		metadata.Region, metadata.EndpointRegionImplicit = g.config.UnsignedRegion, true
		region := cognitoEndpointRegion(r.Host)
		if region == "" {
			region = cognitoHostedEndpointRegion(r.Host)
		}
		if region != "" {
			metadata.Region, metadata.EndpointRegionImplicit = region, false
		}
		metadata.Partition = awscatalog.RegionPartition(metadata.Region)
		BindRequestTransport(r, &metadata)
		hosted.ServeOAuth(w, r.WithContext(awsctx.WithMetadata(r.Context(), metadata)))
		return true
	}
	return false
}

func cognitoHostedEndpointRegion(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	prefix, endpoint, ok := strings.Cut(strings.TrimSuffix(strings.ToLower(host), "."), ".auth.")
	if !ok || prefix == "" || strings.Contains(prefix, ".") {
		return ""
	}
	region, suffix, ok := strings.Cut(endpoint, ".")
	if !ok {
		return ""
	}
	switch awscatalog.RegionPartition(region) {
	case "aws", "aws-us-gov":
		if suffix == "amazoncognito.com" {
			return region
		}
	case "aws-cn":
		if suffix == "amazoncognito.com.cn" {
			return region
		}
	}
	return ""
}
