package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	api "stackd/internal/awsapi/codepipeline"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/codepipeline"
)

func (a *CodePipelineActions) source(ctx context.Context, request codepipeline.ActionRequest) (codepipeline.ActionResult, error) {
	configuration := request.Action.Configuration
	bucket, key := string(configuration["S3Bucket"]), string(configuration["S3ObjectKey"])
	version := ""
	for _, override := range request.SourceRevisionOverrides {
		if pipelineString(override.ActionName) != pipelineString(request.Action.Name) {
			continue
		}
		switch pipelineString(override.RevisionType) {
		case "S3_OBJECT_KEY":
			key = pipelineString(override.RevisionValue)
		case "S3_OBJECT_VERSION_ID":
			version = pipelineString(override.RevisionValue)
		}
	}
	if request.ExternalExecutionID == "" {
		object, err := a.sourceObject(ctx, bucket, key, version)
		if err != nil {
			return codepipeline.ActionResult{}, err
		}
		version = pipelineString(object.VersionId)
		summary := "Amazon S3 version id: " + version
		return codepipeline.ActionResult{Status: "InProgress", ExternalExecutionID: version, Summary: summary,
			Revision:        &codepipeline.SourceRevision{ActionName: pipelineString(request.Action.Name), ArtifactName: request.OutputArtifacts[0].Name, RevisionID: version, Summary: summary},
			OutputVariables: api.OutputVariablesMap{"BucketName": api.OutputVariablesValue(bucket), "ObjectKey": api.OutputVariablesValue(key), "VersionId": api.OutputVariablesValue(version), "ETag": api.OutputVariablesValue(strings.Trim(pipelineString(object.ETag), "\""))}}, nil
	}
	// The first transition retained this exact source version before any copy.
	// Retrying the effect writes the same bytes to the same reserved artifact key.
	version = request.ExternalExecutionID
	artifact := request.OutputArtifacts[0]
	copySource := url.PathEscape(bucket) + "/" + url.PathEscape(key) + "?versionId=" + url.QueryEscape(version)
	input := &s3api.CopyObjectInput{Bucket: new(s3api.BucketName(artifact.Bucket)), Key: new(s3api.ObjectKey(artifact.Key)), CopySource: new(s3api.CopySource(copySource)), ServerSideEncryption: new(s3api.ServerSideEncryption("aws:kms"))}
	// S3 owns first-use creation of its default AWS-managed key.
	if request.ArtifactStore.EncryptionKey != nil {
		input.SSEKMSKeyId = new(s3api.SSEKMSKeyId(pipelineArtifactKey(request.ArtifactStore)))
	}
	raw, err := pipelineCommand(ctx, a.S3, "s3", "CopyObject", input)
	if err != nil {
		return codepipeline.ActionResult{}, err
	}
	copied := raw.(*s3api.CopyObjectOutput)
	artifact.VersionID, artifact.RevisionID = pipelineString(copied.VersionId), version
	artifact.ETag = pipelineString(copied.CopyObjectResult.ETag)
	return codepipeline.ActionResult{Status: "Succeeded", ExternalExecutionID: version, Summary: "Amazon S3 version id: " + version, Artifacts: []codepipeline.Artifact{artifact}}, nil
}

// LatestSourceRevision observes S3 under the pipeline's current role authority.
// It does not copy artifacts or admit an execution; the polling owner commits
// the observed revision with execution intent after checking its retained claim.
func (a *CodePipelineActions) LatestSourceRevision(ctx context.Context, request codepipeline.SourcePollRequest) (string, error) {
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: request.Partition, AccountID: request.AccountID, Region: request.Region, ParentEventID: request.ParentEventID})
	// Session ownership is the source watcher, not each observation lease.
	// A stable bounded name reuses the existing expiring session cache.
	session := sha256.Sum256([]byte(request.Incarnation + "/" + pipelineString(request.Action.Name)))
	ctx, err := a.roleContext(ctx, codepipeline.ActionRequest{
		Scope: request.Scope, PipelineARN: request.PipelineARN, RoleARN: request.RoleARN,
		ActionExecutionID: hex.EncodeToString(session[:16]), Action: request.Action,
	})
	if err != nil {
		return "", err
	}
	bucket, key := string(request.Action.Configuration["S3Bucket"]), string(request.Action.Configuration["S3ObjectKey"])
	object, err := a.sourceObject(ctx, bucket, key, "")
	if err != nil {
		if rejected, ok := err.(*awswire.Error); ok && rejected.StatusCode == 403 {
			return "", &awswire.Error{Code: "PermissionError", StatusCode: 400,
				Message: fmt.Sprintf("Could not access the Amazon S3 object: \"%s/%s\". Make sure that the names of the bucket and object are both correct, and that the pipeline IAM role has sufficient permissions to access this bucket.", bucket, key)}
		}
		if rejected, ok := err.(*awswire.Error); ok && rejected.StatusCode == 404 {
			return "", &awswire.Error{Code: "ConfigurationError", StatusCode: 400,
				Message: fmt.Sprintf("Could not access the Amazon S3 object: \"%s/%s\". Make sure that the names of the bucket and object are both correct.", bucket, key)}
		}
		return "", err
	}
	return pipelineString(object.VersionId), nil
}

func (a *CodePipelineActions) sourceObject(ctx context.Context, bucket, key, version string) (*s3api.HeadObjectOutput, error) {
	versioning, err := pipelineCommand(ctx, a.S3, "s3", "GetBucketVersioning", &s3api.GetBucketVersioningInput{Bucket: new(s3api.BucketName(bucket))})
	if err != nil {
		return nil, err
	}
	if pipelineString(versioning.(*s3api.GetBucketVersioningOutput).Status) != "Enabled" {
		return nil, fmt.Errorf("CodePipeline S3 source bucket versioning must be enabled")
	}
	in := &s3api.HeadObjectInput{Bucket: new(s3api.BucketName(bucket)), Key: new(s3api.ObjectKey(key))}
	if version != "" {
		in.VersionId = new(s3api.ObjectVersionId(version))
	}
	raw, err := pipelineCommand(ctx, a.S3, "s3", "HeadObject", in)
	if err != nil {
		return nil, err
	}
	object := raw.(*s3api.HeadObjectOutput)
	if pipelineString(object.VersionId) == "" {
		return nil, fmt.Errorf("CodePipeline S3 source has no object version")
	}
	return object, nil
}
