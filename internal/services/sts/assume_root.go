package sts

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

var rootAccountID = regexp.MustCompile(`^[0-9]{12}$`)

func isGlobalSTSEndpoint(host string) bool {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return strings.EqualFold(strings.TrimSuffix(host, "."), "sts.amazonaws.com")
}

func (s *Service) assumeRoot(ctx context.Context) (*stsapi.AssumeRootOutput, *awswire.Error) {
	return withSignedSession(s, ctx, "AssumeRoot", (*signedSession).assumeRoot)
}

func (s *signedSession) assumeRoot(ctx context.Context) (*stsapi.AssumeRootOutput, *awswire.Error) {
	input, ok := awsapi.Input[stsapi.AssumeRootInput](ctx)
	if !ok {
		return nil, stsValidation("Missing AssumeRoot input.")
	}
	m := awsctx.FromContext(ctx)
	if m.Region == "aws-global" {
		return nil, &awswire.Error{Code: "InvalidAction", Message: "Unknown Operation", StatusCode: 400}
	}
	accountID, targetARN, apiErr := rootTarget(value(input.TargetPrincipal), m.Partition)
	if apiErr != nil {
		return nil, apiErr
	}
	if input.TaskPolicyArn == nil || !identity.ValidRootTaskPolicyARN(m.Partition, value(input.TaskPolicyArn.Arn)) {
		return nil, stsValidation("Request must contain valid AWS managed task policy ARN")
	}
	taskARN := value(input.TaskPolicyArn.Arn)
	duration := 15 * time.Minute
	if input.DurationSeconds != nil {
		duration = time.Duration(*input.DurationSeconds) * time.Second
	}
	if duration < 0 || duration > 15*time.Minute {
		return nil, stsValidation("DurationSeconds must be between 0 and 900.")
	}
	parent, ctx, apiErr := s.parent(ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	if parent.PrincipalID == parent.AccountID || (parent.SessionType != "" && parent.SessionType != identity.SessionTypeAssumeRole) {
		return nil, stsDenied("AssumeRoot requires an IAM user or assumed-role caller.")
	}
	instant := s.now().UTC()
	request := authorization.Request{Action: "sts:AssumeRoot", ResourceARN: targetARN,
		Context: map[string][]string{"sts:TaskPolicyArn": {taskARN}}, EvaluationTime: &instant}
	if apiErr := s.authorizer.Authorize(ctx, request); apiErr != nil {
		return nil, apiErr
	}
	if s.rootSessions == nil || s.roles == nil {
		return nil, stsDenied("Centralized root access is unavailable.")
	}
	if err := s.rootSessions.CheckRootSession(ctx, accountID, taskARN); err != nil {
		var apiErr *awswire.Error
		if errors.As(err, &apiErr) {
			return nil, apiErr
		}
		return nil, stsDenied("The caller cannot assume root in the requested member account.")
	}
	// The IAM policy source borrows the signed-session transaction. Organizations
	// eligibility comes from its separate authorization snapshot. The resolved
	// task document is fixed in the new token.
	policyMetadata := awsctx.FromContext(ctx)
	policyMetadata.AccountID = accountID
	documents, err := s.roles.ResolveManagedPolicyDocuments(awsctx.WithMetadata(ctx, policyMetadata), []string{taskARN})
	if err != nil || len(documents) != 1 {
		return nil, stsDenied("The requested root task policy is unavailable.")
	}
	if apiErr := s.checkRegion(ctx, accountID, instant); apiErr != nil {
		return nil, apiErr
	}
	credential, err := s.credentials.IssueRootSession(ctx, parent, identity.RootSessionSpec{
		AccountID: accountID, Partition: m.Partition, Duration: duration,
		TaskPolicyARN: taskARN, TaskPolicyDocument: documents[0],
	})
	if err != nil {
		return nil, stsCredentialError(err)
	}
	output := &stsapi.AssumeRootOutput{Credentials: credentialOutput(credential)}
	if credential.SourceIdentity != "" {
		output.SourceIdentity = ptr(stsapi.SourceIdentityType(credential.SourceIdentity))
	}
	return output, nil
}

func rootTarget(value, partition string) (accountID, arn string, apiErr *awswire.Error) {
	if rootAccountID.MatchString(value) {
		return value, "arn:" + partition + ":iam::" + value + ":root", nil
	}
	parts := strings.SplitN(value, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != partition || parts[2] != "iam" || parts[3] != "" || !rootAccountID.MatchString(parts[4]) || parts[5] != "root" {
		return "", "", stsValidation("Request must contain a valid target principal")
	}
	return parts[4], value, nil
}
