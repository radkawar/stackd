package integrations

import (
	"context"
	"fmt"
	"net/url"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayv2"
	"stackd/internal/services/s3"
	"strings"
)

type APIGatewayV2TruststoreObjects interface {
	GetObject(context.Context, *api.GetObjectInput) (*s3.ObjectResponse[api.GetObjectOutput], *awswire.Error)
}
type APIGatewayV2Truststores struct{ S3 APIGatewayV2TruststoreObjects }

func (a APIGatewayV2Truststores) Truststore(ctx context.Context, scope apigatewayv2.Scope, uri, version string) ([]byte, error) {
	if a.S3 == nil {
		return nil, fmt.Errorf("API Gateway S3 truststore owner is not configured")
	}
	u, e := url.Parse(uri)
	if e != nil || u.Scheme != "s3" || u.Host == "" || strings.TrimPrefix(u.Path, "/") == "" {
		return nil, fmt.Errorf("invalid S3 truststore URI")
	}
	in := &api.GetObjectInput{Bucket: new(api.BucketName(u.Host)), Key: new(api.ObjectKey(strings.TrimPrefix(u.Path, "/")))}
	if version != "" {
		in.VersionId = new(api.ObjectVersionId(version))
	}
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = scope.Partition, scope.AccountID, scope.Region
	m.TransportKnown, m.SecureTransport = true, true
	out, wire := a.S3.GetObject(awsctx.WithViaService(awsctx.WithMetadata(ctx, m), "apigateway.amazonaws.com"), in)
	if wire != nil {
		return nil, wire
	}
	if len(out.Output.Body) > 1<<20 {
		return nil, fmt.Errorf("API Gateway truststore exceeds 1 MiB")
	}
	return out.Output.Body, nil
}
