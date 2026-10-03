package integrations

import (
	"context"
	"encoding/json"
	"time"

	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/codepipeline"
)

type pipelineArtifactStatement struct {
	Effect    string                         `json:"Effect"`
	Action    []string                       `json:"Action"`
	Resource  []string                       `json:"Resource"`
	Condition map[string]map[string][]string `json:"Condition,omitempty"`
}

// Artifact credentials are independent, short-lived role sessions. They retain
// current role authority but cannot read unrelated pipeline-bucket objects.
func (a *CodePipelineActions) lambdaArtifactCredentials(ctx context.Context, request codepipeline.ActionRequest) (identity.Credential, error) {
	resources := make([]string, 0, len(request.InputArtifacts)+len(request.OutputArtifacts))
	for _, artifact := range request.InputArtifacts {
		resources = append(resources, pipelineArtifactARN(request.Partition, artifact))
	}
	for _, artifact := range request.OutputArtifacts {
		resources = append(resources, pipelineArtifactARN(request.Partition, artifact))
	}
	statements := make([]pipelineArtifactStatement, 0, 3)
	if n := len(request.InputArtifacts); n > 0 {
		statements = append(statements, pipelineArtifactStatement{Effect: "Allow", Action: []string{"s3:GetObject", "s3:GetObjectVersion"}, Resource: resources[:n]})
	}
	if len(request.OutputArtifacts) > 0 {
		statements = append(statements, pipelineArtifactStatement{Effect: "Allow", Action: []string{"s3:PutObject", "s3:PutObjectAcl", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"}, Resource: resources[len(request.InputArtifacts):]})
	}
	if len(resources) > 0 {
		// The artifact object's S3 encryption context restricts key use without
		// requiring an extra DescribeKey permission merely to resolve an alias.
		statements = append(statements, pipelineArtifactStatement{Effect: "Allow", Action: []string{"kms:Decrypt", "kms:GenerateDataKey"}, Resource: []string{"*"}, Condition: map[string]map[string][]string{"StringEquals": {"kms:EncryptionContext:aws:s3:arn": resources}}})
	} else {
		statements = append(statements, pipelineArtifactStatement{Effect: "Deny", Action: []string{"*"}, Resource: []string{"*"}})
	}
	// TODO: Comeback — calibrate the complete native artifact-credential action
	// matrix beyond per-artifact read/write isolation and role authority.
	policy, err := json.Marshal(struct {
		Version   string                      `json:"Version"`
		Statement []pipelineArtifactStatement `json:"Statement"`
	}{Version: "2012-10-17", Statement: statements})
	if err != nil {
		return identity.Credential{}, err
	}
	name := "AWSCodePipeline-" + request.InvocationJob.ID
	principal := awsctx.ServicePrincipal{Name: "codepipeline.amazonaws.com", SourceARN: request.PipelineARN, Type: "AWSService"}
	if role := pipelineString(request.Action.RoleArn); role != "" {
		// Action roles trust the pipeline role, not necessarily the service
		// principal. Use the same role chain as actual action invocation.
		base, err := a.sessions.context(ctx, a.Roles, principal, request.RoleARN, "AWSCodePipeline-"+request.ActionExecutionID, "")
		if err != nil {
			return identity.Credential{}, err
		}
		out, err := pipelineCommand(base, a.STS, "sts", "AssumeRole", &stsapi.AssumeRoleInput{RoleArn: new(stsapi.ArnType(role)), RoleSessionName: new(stsapi.RoleSessionNameType(name)), DurationSeconds: new(stsapi.RoleDurationSecondsType(900)), Policy: new(stsapi.UnrestrictedSessionPolicyDocumentType(policy))})
		if err != nil {
			return identity.Credential{}, err
		}
		return a.Roles.Credentials.Resolve(ctx, pipelineString(out.(*stsapi.AssumeRoleOutput).Credentials.AccessKeyId))
	}
	credential, rejected := a.Roles.assume(ctx, principal, request.RoleARN, identity.RoleSessionSpec{SessionName: name, Duration: 15 * time.Minute, Policies: []string{string(policy)}, HasSessionPolicy: true}, "")
	if rejected != nil {
		return identity.Credential{}, rejected
	}
	return credential, nil
}
