package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"stackd/internal/awsapi"
	glueapi "stackd/internal/awsapi/glue"
	s3api "stackd/internal/awsapi/s3"
	secretapi "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/glue"
	"stackd/internal/services/s3"
)

// GlueCrawlerObjects keeps object authorization, encryption and bytes in S3.
// The crawler receives no authority from its creator's identity.
type GlueCrawlerObjects interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	GetObject(context.Context, *s3api.GetObjectInput) (*s3.ObjectResponse[s3api.GetObjectOutput], *awswire.Error)
}

func (a *GlueCrawlers) listObjectsV2(ctx context.Context, input *s3api.ListObjectsV2Input) (*s3api.ListObjectsV2Output, *awswire.Error) {
	model, _ := awscatalog.LookupService("s3")
	operation, _ := model.Operation("ListObjectsV2")
	output, rejected := a.S3.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		return nil, rejected
	}
	result, ok := output.(*s3api.ListObjectsV2Output)
	if !ok {
		return nil, &awswire.Error{Code: "InternalServiceException", Message: "Unexpected S3 list response", StatusCode: 500}
	}
	return result, nil
}

type GlueCrawlerSecrets interface {
	GetSecretValue(context.Context, *secretapi.GetSecretValueInput) (*secretapi.GetSecretValueOutput, *awswire.Error)
}

// GlueCrawlers enters ordinary service commands under current Glue execution-role
// authority. No object bytes, credentials or policy decisions are cached here.
type GlueCrawlers struct {
	Roles ServiceRoles
	S3    GlueCrawlerObjects
}

func (a *GlueCrawlers) RoleContext(ctx context.Context, scope glue.Scope, roleARN, sourceARN string) (context.Context, error) {
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = scope.Partition, scope.AccountID, scope.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	credential, rejected := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: "glue.amazonaws.com", SourceARN: sourceARN, Type: "AWSService"}, roleARN, identity.RoleSessionSpec{SessionName: "GlueCrawler"}, "")
	if rejected != nil {
		return nil, rejected
	}
	ctx, rejected = serviceRoleRequestContext(ctx, credential, scope.Region, "glue.amazonaws.com")
	if rejected != nil {
		return nil, rejected
	}
	return ctx, nil
}

// Validate checks S3 target existence under the current execution role through
// metadata-only commands. It joins the caller's transaction and never reads an
// object body or launches a native crawler/JDBC process.
func (a *GlueCrawlers) Validate(ctx context.Context, scope glue.Scope, roleARN, sourceARN string, targets glueapi.CrawlerTargets) error {
	if len(targets.S3Targets) == 0 {
		return nil
	}
	ctx, err := a.RoleContext(ctx, scope, roleARN, sourceARN)
	if err != nil {
		return err
	}
	for _, target := range targets.S3Targets {
		if target.Path == nil {
			return fmt.Errorf("glue crawler S3 target requires a path")
		}
		location, err := url.Parse(string(*target.Path))
		if err != nil || location.Scheme != "s3" || location.Host == "" || location.User != nil {
			return fmt.Errorf("glue crawler S3 target is invalid")
		}
		_, rejected := a.listObjectsV2(ctx, &s3api.ListObjectsV2Input{
			Bucket:  new(s3api.BucketName(location.Host)),
			Prefix:  new(s3api.Prefix(strings.TrimPrefix(location.Path, "/"))),
			MaxKeys: new(s3api.MaxKeys(1)),
		})
		if rejected != nil {
			return rejected
		}
	}
	return nil
}

func (a *GlueCrawlers) List(ctx context.Context, bucket, prefix, token string) (glue.CrawlerObjectPage, error) {
	input := &s3api.ListObjectsV2Input{Bucket: new(s3api.BucketName(bucket)), Prefix: new(s3api.Prefix(prefix))}
	if token != "" {
		input.ContinuationToken = new(s3api.Token(token))
	}
	out, rejected := a.listObjectsV2(ctx, input)
	if rejected != nil {
		return glue.CrawlerObjectPage{}, rejected
	}
	page := glue.CrawlerObjectPage{Objects: make([]glue.CrawlerObject, 0, len(out.Contents))}
	for _, object := range out.Contents {
		if object.Key == nil {
			continue
		}
		entry := glue.CrawlerObject{Key: string(*object.Key)}
		if object.Size != nil {
			entry.Size = int64(*object.Size)
		}
		page.Objects = append(page.Objects, entry)
	}
	if out.NextContinuationToken != nil {
		page.NextToken = string(*out.NextContinuationToken)
	}
	return page, nil
}

func (a *GlueCrawlers) Read(ctx context.Context, bucket, key string) ([]byte, error) {
	out, rejected := a.S3.GetObject(ctx, &s3api.GetObjectInput{Bucket: new(s3api.BucketName(bucket)), Key: new(s3api.ObjectKey(key))})
	if rejected != nil {
		return nil, rejected
	}
	return out.Output.Body, nil
}

// GlueConnectionSecrets resolves customer-managed JDBC secrets through the
// existing Secrets Manager/KMS authorization boundary. It does not create an
// implicit secret for an inline Glue connection password.
type GlueConnectionSecrets struct{ Secrets GlueCrawlerSecrets }

func (a GlueConnectionSecrets) Read(ctx context.Context, id string) (string, string, error) {
	out, rejected := a.Secrets.GetSecretValue(ctx, &secretapi.GetSecretValueInput{SecretId: new(secretapi.SecretIdType(id))})
	if rejected != nil {
		return "", "", rejected
	}
	if out.SecretString == nil {
		return "", "", fmt.Errorf("glue JDBC connection requires a JSON string secret")
	}
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(*out.SecretString), &credentials); err != nil {
		return "", "", fmt.Errorf("glue JDBC connection secret is not a valid credentials object")
	}
	if credentials.Username == "" || credentials.Password == "" {
		return "", "", fmt.Errorf("glue JDBC connection secret requires username and password")
	}
	return credentials.Username, credentials.Password, nil
}

var _ glue.CrawlerSource = (*GlueCrawlers)(nil)
