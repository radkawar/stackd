package integrations

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/codepipeline"
)

// AppConfigPipelineArtifacts resolves the configuration member and its real S3
// archive from an immutable action execution, including completed executions.
type AppConfigPipelineArtifacts interface {
	ResolveDeployment(context.Context, codepipeline.Scope, string, string) (codepipeline.ActionRequest, bool, error)
}

func (a *AppConfigEffects) retrievePipeline(ctx context.Context, profile appconfig.Profile, version string) (appconfig.ConfigurationContent, error) {
	var result appconfig.ConfigurationContent
	if a.PipelineArtifacts == nil || a.Objects == nil {
		return result, fmt.Errorf("AppConfig CodePipeline artifact owner is unavailable")
	}
	scope := codepipeline.Scope{Partition: profile.Partition, AccountID: profile.AccountID, Region: profile.Region}
	action, found, err := a.PipelineArtifacts.ResolveDeployment(ctx, scope, strings.TrimPrefix(profile.LocationURI, "codepipeline://"), version)
	if err != nil {
		return result, err
	}
	if !found {
		return result, pipelineSourceUnavailable()
	}
	artifact := action.InputArtifacts[0]
	// CodePipeline sources have no retrieval role. Native StartDeployment uses
	// the current caller's artifact authority, not a cached successful deployment.
	forwarder, rejected := appConfigPipelineForwarder(profile.Scope)
	if rejected != nil {
		return result, rejected
	}
	ctx = awsctx.WithViaService(appConfigScopeContext(ctx, profile.Scope), forwarder)
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID, metadata.ParentEventID = uuid.NewString(), apievents.EventID(ctx)
	metadata.InvokedBy, metadata.SourceIP, metadata.UserAgent = "AWS Internal", "AWS Internal", "AWS Internal"
	ctx = awsctx.WithMetadata(ctx, metadata)
	object, rejected := a.Objects.GetObject(ctx, &s3api.GetObjectInput{Bucket: new(s3api.BucketName(artifact.Bucket)), Key: new(s3api.ObjectKey(artifact.Key))})
	if rejected != nil {
		switch rejected.Code {
		case "NoSuchKey", "NoSuchVersion", "NoSuchBucket":
			return result, pipelineSourceUnavailable()
		case "AccessDenied":
			return result, appConfigFailure(fmt.Sprintf("Unable to access the artifact with Amazon S3 object key '%s' located in the Amazon S3 artifact bucket '%s'. The provided role does not have sufficient permissions.", artifact.Key, artifact.Bucket))
		default:
			return result, appConfigFailure("Unable to retrieve the CodePipeline configuration artifact: " + rejected.Message)
		}
	}
	archive, err := zip.NewReader(bytes.NewReader(object.Output.Body), int64(len(object.Output.Body)))
	if err != nil {
		return result, appConfigFailure("Invalid CodePipeline configuration ZIP: " + err.Error())
	}
	member := string(action.Action.Configuration["InputArtifactConfigurationPath"])
	for _, file := range archive.File {
		if file.Name != member || file.FileInfo().IsDir() {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return result, appConfigFailure("Unable to open configuration ZIP member: " + err.Error())
		}
		defer reader.Close()
		result.Content, err = io.ReadAll(reader)
		if err != nil {
			return result, appConfigFailure("Unable to read configuration ZIP member: " + err.Error())
		}
		result.Version, result.ContentType = version, "application/octet-stream"
		return result, nil
	}
	return result, appConfigFailure("Configuration file does not exist in the CodePipeline artifact: " + member)
}

func pipelineSourceUnavailable() *awswire.Error {
	// Native captures return this modeled error for an unknown action version
	// and for an authorized caller whose referenced artifact has been removed.
	return &awswire.Error{Code: "InternalServerException", StatusCode: 500}
}

func appConfigPipelineForwarder(scope appconfig.Scope) (string, *awswire.Error) {
	// Captured CalledVia values are regional numeric identifiers, not the public
	// AppConfig service principal. Never use one region's identity in another.
	if scope.Partition == "aws" {
		switch scope.Region {
		case "us-east-1":
			return "460678247002", nil
		case "us-west-2":
			return "783816728759", nil
		case "eu-west-1":
			return "242796738427", nil
		}
	}
	// TODO: Comeback — calibrate remaining regional/partition forwarding identities
	// through native artifact reads; do not invent an authorization context.
	return "", &awswire.Error{Code: "NotImplementedException", StatusCode: 501,
		Message: "AppConfig CodePipeline artifact forwarding is not implemented for " + scope.Partition + "/" + scope.Region}
}
