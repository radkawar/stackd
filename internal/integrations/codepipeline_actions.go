package integrations

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awscatalog"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/codepipeline"
)

// CodePipelineActions routes accepted actions through real service owners. It
// keeps no build/deployment state: the provider handle belongs to the execution.
type CodePipelineActions struct {
	Roles                                      ServiceRoles
	S3, CodeBuild, AppConfig, STS, SNS, Lambda awscommands.CommandExecutor
	sessions                                   serviceRoleSessions
}

func (a *CodePipelineActions) Execute(ctx context.Context, request codepipeline.ActionRequest) (codepipeline.ActionResult, error) {
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: request.Partition, AccountID: request.AccountID, Region: request.Region, ParentEventID: request.ParentEventID})
	ctx, err := a.roleContext(ctx, request)
	if err != nil {
		if rejected, ok := err.(*awswire.Error); ok && (rejected.StatusCode == 403 || rejected.Code == "NoSuchEntity") {
			return codepipeline.ActionResult{Status: "Failed", ErrorCode: "PermissionError", Summary: "The provided role cannot be assumed: '" + err.Error() + "'"}, nil
		}
		return codepipeline.ActionResult{}, err
	}
	switch pipelineString(request.Action.ActionTypeId.Provider) {
	case "S3":
		if pipelineString(request.Action.ActionTypeId.Category) == "Deploy" {
			return a.deployS3(ctx, request)
		}
		return a.source(ctx, request)
	case "CodeBuild":
		return a.build(ctx, request)
	case "AppConfig":
		return a.deploy(ctx, request)
	case "Manual":
		return a.notifyApproval(ctx, request)
	case "Lambda":
		return a.invokeLambda(ctx, request)
	default:
		return codepipeline.ActionResult{}, fmt.Errorf("CodePipeline provider %s has no execution owner", pipelineString(request.Action.ActionTypeId.Provider))
	}
}

func (a *CodePipelineActions) roleContext(ctx context.Context, request codepipeline.ActionRequest) (context.Context, error) {
	principal := awsctx.ServicePrincipal{Name: "codepipeline.amazonaws.com", SourceARN: request.PipelineARN, Type: "AWSService"}
	name := "AWSCodePipeline-" + request.ActionExecutionID
	base, err := a.sessions.context(ctx, a.Roles, principal, request.RoleARN, name, "")
	if err != nil {
		return nil, err
	}
	role := pipelineString(request.Action.RoleArn)
	if role == "" {
		return base, nil
	}
	key := serviceSessionKey{roleARN: role, sessionName: name, service: principal.Name, sourceARN: request.PipelineARN, issuerARN: request.RoleARN}
	return a.sessions.contextFor(base, a.Roles, key, func(ctx context.Context) (identity.Credential, error) {
		out, err := pipelineCommand(ctx, a.STS, "sts", "AssumeRole", &stsapi.AssumeRoleInput{RoleArn: new(stsapi.ArnType(role)), RoleSessionName: new(stsapi.RoleSessionNameType(name)), DurationSeconds: new(stsapi.RoleDurationSecondsType(3600))})
		if err != nil {
			return identity.Credential{}, err
		}
		return a.Roles.Credentials.Resolve(ctx, string(*out.(*stsapi.AssumeRoleOutput).Credentials.AccessKeyId))
	})
}

func pipelineCommand(ctx context.Context, owner awscommands.CommandExecutor, service, operation string, input any) (any, error) {
	if owner == nil {
		return nil, fmt.Errorf("CodePipeline %s owner is unavailable", service)
	}
	metadata := awsctx.FromContext(ctx)
	if parent := apievents.EventID(ctx); parent != "" {
		metadata.ParentEventID = parent
	}
	metadata.RequestID = uuid.NewString()
	metadata.InvokedBy = "codepipeline.amazonaws.com"
	metadata.SourceIP, metadata.UserAgent = "codepipeline.amazonaws.com", "codepipeline.amazonaws.com"
	metadata.TransportKnown, metadata.SecureTransport = true, true
	model, _ := awscatalog.LookupService(service)
	command, _ := model.Operation(operation)
	out, rejected := owner.ExecuteCommand(awsctx.WithMetadata(ctx, metadata), awsapi.DecodedRequest{Operation: command, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		return nil, rejected
	}
	return out, nil
}

func pipelineString[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
