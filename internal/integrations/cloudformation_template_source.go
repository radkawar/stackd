package integrations

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/s3"
)

// CloudFormationTemplateObjects is the existing S3 read/authorization authority.
type CloudFormationTemplateObjects interface {
	GetObject(context.Context, *api.GetObjectInput) (*s3.ObjectResponse[api.GetObjectOutput], *awswire.Error)
}

// CloudFormationTemplateSource reads S3 URLs locally; it never fetches arbitrary
// URLs or falls back to an AWS network endpoint.
type CloudFormationTemplateSource struct{ S3 CloudFormationTemplateObjects }

var cfnS3TemplateHost = regexp.MustCompile(`^(?:(.+)\.)?s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$`)

func (a CloudFormationTemplateSource) ReadTemplate(ctx context.Context, location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return "", fmt.Errorf("TemplateURL must be an HTTPS S3 object URL")
	}
	match := cfnS3TemplateHost.FindStringSubmatch(u.Hostname())
	if match == nil {
		return "", fmt.Errorf("TemplateURL must refer to an S3 endpoint")
	}
	bucket, key := match[1], strings.TrimPrefix(u.Path, "/")
	if bucket == "" {
		var found bool
		bucket, key, found = strings.Cut(key, "/")
		if !found {
			return "", fmt.Errorf("TemplateURL requires a bucket and object key")
		}
	}
	if bucket == "" || key == "" {
		return "", fmt.Errorf("TemplateURL requires a bucket and object key")
	}
	input := &api.GetObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key))}
	if version := u.Query().Get("versionId"); version != "" {
		input.VersionId = new(api.ObjectVersionId(version))
	}
	m := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		m.ParentEventID = parent
	}
	m.RequestID = uuid.NewString()
	m.InvokedBy = "cloudformation.amazonaws.com"
	m.SourceIP, m.UserAgent = "cloudformation.amazonaws.com", "cloudformation.amazonaws.com"
	m.TransportKnown, m.SecureTransport = true, true
	out, rejected := a.S3.GetObject(awsctx.WithMetadata(ctx, m), input)
	if rejected != nil {
		return "", rejected
	}
	if len(out.Output.Body) > 1024*1024 {
		return "", fmt.Errorf("TemplateURL object exceeds 1048576 bytes")
	}
	return string(out.Output.Body), nil
}
