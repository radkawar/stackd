package s3

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func s3EndpointHost(host string) string {
	if strings.Contains(host, ":") {
		if name, _, err := net.SplitHostPort(host); err == nil {
			host = name
		}
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func s3RegionDomain(partition, region string) string {
	suffix := "amazonaws.com"
	if partition == "aws-cn" {
		suffix += ".cn"
	}
	return region + "." + suffix
}

func s3EndpointRegion(host string) string {
	host = s3EndpointHost(host)
	host, aws := strings.CutSuffix(host, ".amazonaws.com")
	if !aws {
		host, aws = strings.CutSuffix(host, ".amazonaws.com.cn")
	}
	if !aws {
		return ""
	}
	// Ordinary bucket and alias routes share regional and legacy s3- hosts.
	if !strings.HasPrefix(host, "s3.") && !strings.HasPrefix(host, "s3-") && !strings.Contains(host, ".s3.") && !strings.Contains(host, ".s3-") {
		return ""
	}
	region := strings.TrimPrefix(host[strings.LastIndexByte(host, '.')+1:], "s3-")
	if awscatalog.RegionPartition(region) == "" {
		return ""
	}
	return region
}

func admitS3Endpoint(host, partition, region, bucket string) *awswire.Error {
	if endpoint := s3EndpointRegion(host); endpoint == "" || endpoint == region {
		return nil
	}
	wire := failure("PermanentRedirect", "The bucket you are attempting to access must be addressed using the specified endpoint. Please send all future requests to this endpoint.", http.StatusMovedPermanently)
	wire.Endpoint = bucket + ".s3-" + s3RegionDomain(partition, region)
	wire.Bucket = bucket
	wire.ResponseHeader = http.Header{"X-Amz-Bucket-Region": {region}}
	return wire
}

func admitS3SigningRegion(ctx context.Context, region string) *awswire.Error {
	m := awsctx.FromContext(ctx)
	var wire *awswire.Error
	if m.ServicePrincipal.Name == "" && m.Region != region {
		if m.AuthenticationMethod == "QueryString" {
			wire = failure("AuthorizationQueryParametersError", fmt.Sprintf("Error parsing the X-Amz-Credential parameter; the region '%s' is wrong; expecting '%s'", m.Region, region), http.StatusBadRequest)
		} else {
			wire = failure("AuthorizationHeaderMalformed", fmt.Sprintf("The authorization header is malformed; the region '%s' is wrong; expecting '%s'", m.Region, region), http.StatusBadRequest)
		}
		wire.Region = region
	}
	if wire != nil {
		wire.ResponseHeader = http.Header{"X-Amz-Bucket-Region": {region}}
	}
	return wire
}
