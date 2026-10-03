package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	api "stackd/internal/awsapi/codepipeline"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/codepipeline"
)

func (a *CodePipelineActions) invokeLambda(ctx context.Context, request codepipeline.ActionRequest) (codepipeline.ActionResult, error) {
	job := request.InvocationJob
	if job == nil {
		return codepipeline.ActionResult{}, fmt.Errorf("lambda action has no retained invocation job")
	}
	function := string(request.Action.Configuration["FunctionName"])
	result := codepipeline.ActionResult{Status: "InProgress", ExternalExecutionID: function, ExternalExecutionURL: pipelineLambdaLogURL(request.Region, function)}
	switch job.Status {
	case "Running":
		return result, nil
	case "Succeeded":
		// Native trusts the worker's result. These are reserved locators, not
		// fabricated bytes or version metadata. Missing output fails when read by
		// the downstream owner, not retroactively in the completed Lambda action.
		result.Status, result.Artifacts, result.OutputVariables = "Succeeded", request.OutputArtifacts, job.OutputVariables
		return result, nil
	case "Failed":
		if job.FailureDetails == nil {
			return codepipeline.ActionResult{}, fmt.Errorf("failed Lambda job has no failure details")
		}
		result.Status = "Failed"
		result.ErrorCode = pipelineString(job.FailureDetails.Type)
		result.ErrorMessage = pipelineString(job.FailureDetails.Message)
		result.Summary = result.ErrorMessage
		return result, nil
	case "Ready":
		credential, err := a.lambdaArtifactCredentials(ctx, request)
		if err != nil {
			return pipelineLambdaError(err, function)
		}
		payload, err := pipelineLambdaPayload(request, credential)
		if err != nil {
			return codepipeline.ActionResult{}, err
		}
		out, err := pipelineCommand(ctx, a.Lambda, "lambda", "Invoke", &lambdaapi.InvokeInput{FunctionName: new(lambdaapi.NamespacedFunctionName(function)), InvocationType: new(lambdaapi.InvocationType("Event")), Payload: payload})
		if err != nil {
			return pipelineLambdaError(err, function)
		}
		if response := out.(*lambdaapi.InvokeOutput); response.StatusCode == nil || *response.StatusCode != 202 {
			return codepipeline.ActionResult{}, fmt.Errorf("lambda event invocation was not accepted")
		}
		result.InvocationAccepted = true
		return result, nil
	default:
		return codepipeline.ActionResult{}, fmt.Errorf("unexpected Lambda job status %q", job.Status)
	}
}

func pipelineLambdaError(err error, function string) (codepipeline.ActionResult, error) {
	if rejected, ok := err.(*awswire.Error); ok {
		code, message := rejected.Code, rejected.Message
		if rejected.Code == "ResourceNotFoundException" {
			code, message = "ConfigurationError", "The AWS Lambda function "+function+" does not exist."
		} else if rejected.StatusCode == 403 {
			code = "PermissionError"
		}
		return codepipeline.ActionResult{Status: "Failed", ErrorCode: code, ErrorMessage: message, Summary: message}, nil
	}
	return codepipeline.ActionResult{}, err
}

func pipelineLambdaLogURL(region, function string) string {
	if _, resource, ok := strings.Cut(function, ":function:"); ok {
		function = resource
	}
	function, _, _ = strings.Cut(function, ":")
	return "https://console.aws.amazon.com/cloudwatch/home?region=" + url.QueryEscape(region) + "#logStream:group=" + url.QueryEscape(url.QueryEscape("/aws/lambda/"+function))
}

type pipelineLambdaArtifact struct {
	Location api.ArtifactLocation `json:"location"`
	Revision *string              `json:"revision"`
	Name     string               `json:"name"`
}

type pipelineLambdaCredential struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	ExpirationTime  int64  `json:"expirationTime"`
}

type pipelineLambdaJobData struct {
	ActionConfiguration api.ActionConfiguration  `json:"actionConfiguration"`
	InputArtifacts      []pipelineLambdaArtifact `json:"inputArtifacts"`
	OutputArtifacts     []pipelineLambdaArtifact `json:"outputArtifacts"`
	ArtifactCredentials pipelineLambdaCredential `json:"artifactCredentials"`
	ContinuationToken   string                   `json:"continuationToken,omitempty"`
	EncryptionKey       *api.EncryptionKey       `json:"encryptionKey,omitempty"`
}

func pipelineLambdaPayload(request codepipeline.ActionRequest, credential identity.Credential) ([]byte, error) {
	data := pipelineLambdaJobData{
		ActionConfiguration: api.ActionConfiguration{Configuration: request.Action.Configuration},
		InputArtifacts:      pipelineLambdaArtifacts(request.InputArtifacts), OutputArtifacts: pipelineLambdaArtifacts(request.OutputArtifacts),
		ArtifactCredentials: pipelineLambdaCredential{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey, SessionToken: credential.SessionToken, ExpirationTime: credential.Expiration.UnixMilli()},
		ContinuationToken:   request.InvocationJob.ContinuationToken, EncryptionKey: request.ArtifactStore.EncryptionKey,
	}
	type jobEnvelope struct {
		ID        string                `json:"id"`
		AccountID string                `json:"accountId"`
		Data      pipelineLambdaJobData `json:"data"`
	}
	return json.Marshal(struct {
		Job jobEnvelope `json:"CodePipeline.job"`
	}{Job: jobEnvelope{ID: request.InvocationJob.ID, AccountID: request.AccountID, Data: data}})
}

func pipelineLambdaArtifacts(artifacts []codepipeline.Artifact) []pipelineLambdaArtifact {
	out := make([]pipelineLambdaArtifact, len(artifacts))
	for i, artifact := range artifacts {
		out[i] = pipelineLambdaArtifact{Name: artifact.Name, Location: api.ArtifactLocation{Type: new(api.ArtifactLocationType("S3")), S3Location: &api.S3ArtifactLocation{BucketName: new(api.S3BucketName(artifact.Bucket)), ObjectKey: new(api.S3ObjectKey(artifact.Key))}}}
		if artifact.RevisionID != "" {
			out[i].Revision = new(artifact.RevisionID)
		}
	}
	return out
}
