package integrations

import (
	"context"
	"fmt"
	"sort"
	"strings"

	runtime "stackd/compute/codebuild"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/s3"
)

// CodeBuildObjectCommands preserves S3's authorization, versions and encryption.
type CodeBuildObjectCommands interface {
	GetObject(context.Context, *api.GetObjectInput) (*s3.ObjectResponse[api.GetObjectOutput], *awswire.Error)
	ListObjectsV2(context.Context, *api.ListObjectsV2Input) (*api.ListObjectsV2Output, *awswire.Error)
	PutObject(context.Context, *api.PutObjectInput) (*api.PutObjectOutput, *awswire.Error)
}
type CodeBuildObjects struct{ S3 CodeBuildObjectCommands }

func codeBuildCommandContext(ctx context.Context) context.Context {
	m := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		m.ParentEventID = parent
	}
	m.RequestID = uuid.NewString()
	m.InvokedBy = "codebuild.amazonaws.com"
	m.SourceIP, m.UserAgent = "codebuild.amazonaws.com", "codebuild.amazonaws.com"
	m.TransportKnown, m.SecureTransport = true, true
	return awsctx.WithMetadata(ctx, m)
}

func (a CodeBuildObjects) Read(ctx context.Context, bucket, key, version string) ([]byte, error) {
	in := &api.GetObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key))}
	if version != "" {
		in.VersionId = new(api.ObjectVersionId(version))
	}
	out, rejected := a.S3.GetObject(codeBuildCommandContext(ctx), in)
	if rejected != nil {
		return nil, rejected
	}
	return out.Output.Body, nil
}

// ReadFolder enumerates current objects under the accepted prefix, then reads
// each through the same execution-role S3/KMS authority as ZIP sources.
func (a CodeBuildObjects) ReadFolder(ctx context.Context, bucket, prefix string) ([]runtime.File, error) {
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		return nil, fmt.Errorf("S3 source folder must end with a slash")
	}
	in := &api.ListObjectsV2Input{Bucket: new(api.BucketName(bucket)), Prefix: new(api.Prefix(prefix))}
	var keys []string
	var listedBytes int64
	found := false
	for {
		out, rejected := a.S3.ListObjectsV2(codeBuildCommandContext(ctx), in)
		if rejected != nil {
			return nil, rejected
		}
		for _, object := range out.Contents {
			found = true
			if object.Key == nil || !strings.HasPrefix(string(*object.Key), prefix) {
				return nil, fmt.Errorf("S3 source listing returned an invalid key")
			}
			key := string(*object.Key)
			// S3 console folder markers do not create source files.
			if strings.HasSuffix(key, "/") {
				continue
			}
			keys = append(keys, key)
			if object.Size != nil {
				listedBytes += int64(*object.Size)
			}
			if len(keys) > 100000 || listedBytes > 512<<20 {
				return nil, fmt.Errorf("S3 source folder exceeds workspace limits")
			}
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		if out.NextContinuationToken == nil || *out.NextContinuationToken == "" || in.ContinuationToken != nil && string(*in.ContinuationToken) == string(*out.NextContinuationToken) {
			return nil, fmt.Errorf("S3 source listing did not advance")
		}
		in.ContinuationToken = new(api.Token(*out.NextContinuationToken))
	}
	if !found {
		return nil, fmt.Errorf("no objects found under S3 prefix")
	}
	sort.Strings(keys)
	files := make([]runtime.File, 0, len(keys))
	var total int64
	for _, key := range keys {
		body, err := a.Read(ctx, bucket, key, "")
		if err != nil {
			return nil, err
		}
		total += int64(len(body))
		if total > 512<<20 {
			return nil, fmt.Errorf("S3 source folder exceeds 512 MiB")
		}
		files = append(files, runtime.File{Path: strings.TrimPrefix(key, prefix), Body: body, Mode: 0600})
	}
	return files, nil
}

func (a CodeBuildObjects) ReadBuildspec(ctx context.Context, bucket, key string) ([]byte, error) {
	out, rejected := a.S3.GetObject(codeBuildCommandContext(ctx), &api.GetObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key))})
	if rejected != nil {
		return nil, rejected
	}
	if out.Region != awsctx.FromContext(ctx).Region {
		return nil, &awswire.Error{Code: "InvalidInputException", Message: "The buildspec S3 bucket must be in the build project's Region.", StatusCode: 400}
	}
	return out.Output.Body, nil
}
func (a CodeBuildObjects) Write(ctx context.Context, bucket, key string, body []byte, kmsKey string) error {
	in := &api.PutObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key)), Body: body, ContentType: new(api.ContentType("application/octet-stream"))}
	if kmsKey != "" {
		in.ServerSideEncryption = new(api.ServerSideEncryption("aws:kms"))
		in.SSEKMSKeyId = new(api.SSEKMSKeyId(kmsKey))
	}
	_, rejected := a.S3.PutObject(codeBuildCommandContext(ctx), in)
	if rejected != nil {
		return rejected
	}
	return nil
}
