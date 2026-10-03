package integrations

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// ECSTaskRoles uses the common IAM transaction and STS session issuer. ECS's
// native admission source ARN is task/*, not the cluster-qualified runtime ARN.
type ECSTaskRoles struct{ ServiceRoles }

func (a ECSTaskRoles) Validate(ctx context.Context, roleARN, taskARN string) error {
	metadata := awsctx.FromContext(ctx)
	role, err := arn.Parse(roleARN)
	if err != nil || role.Partition != metadata.Partition || role.Service != "iam" || role.Region != "" || role.AccountID != metadata.AccountID || !strings.HasPrefix(role.Resource, "role/") || len(role.Resource) == len("role/") {
		return ecsTaskRoleDenied(roleARN)
	}
	return a.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		resolved, err := a.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			return ecsTaskRoleDenied(roleARN)
		}
		if rejected := a.Authorizer.Authorize(ctx, authorization.Request{
			Action: "iam:PassRole", ResourceARN: roleARN, EvaluationTime: &now,
			Context: map[string][]string{"iam:PassedToService": {"ecs-tasks.amazonaws.com"}, "iam:AssociatedResourceArn": {taskARN}},
		}); rejected != nil {
			return rejected
		}
		source := "arn:" + metadata.Partition + ":ecs:" + metadata.Region + ":" + metadata.AccountID + ":task/*"
		service := awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "ecs-tasks.amazonaws.com", SourceARN: source, Type: "AWSService"})
		if rejected := a.ServiceRoles.trust(service, resolved, identity.RoleSessionSpec{SessionName: "*"}, now, ""); rejected != nil {
			return ecsTaskRoleDenied(roleARN)
		}
		return nil
	})
}

func (a ECSTaskRoles) Assume(ctx context.Context, roleARN, taskARN string) (identity.Credential, *awswire.Error) {
	session := taskARN[strings.LastIndexByte(taskARN, '/')+1:]
	// TODO: Comeback establish the exact native credential-vending SourceArn;
	// captures prove admission's literal task/* but not the runtime ARN shape.
	return a.ServiceRoles.assume(ctx, awsctx.ServicePrincipal{Name: "ecs-tasks.amazonaws.com", SourceARN: taskARN, Type: "AWSService"}, roleARN, identity.RoleSessionSpec{SessionName: session, RequestParentEventID: awsctx.FromContext(ctx).ParentEventID}, "")
}

func ecsTaskRoleDenied(roleARN string) *awswire.Error {
	return &awswire.Error{Code: "ClientException", StatusCode: 400, Message: "ECS was unable to assume the role '" + roleARN + "' that was provided for this task. Please verify that the role being passed has the proper trust relationship and permissions and that your IAM user has permissions to pass this role."}
}
