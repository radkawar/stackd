package ecs

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
)

// Deployment and revision identities share the admitted ecs-svc numeric suffix,
// but have distinct resource types and remain scoped to their owning service.
type terraformDeploymentKey struct {
	ServiceKey
	ID string
}

func (k terraformDeploymentKey) ARN() string {
	return "arn:" + k.Partition + ":ecs:" + k.Region + ":" + k.AccountID + ":service-deployment/" + k.Name + "/" + k.ServiceName + "/" + k.ID
}

func terraformDeploymentID(key ServiceKey, id string) terraformDeploymentKey {
	return terraformDeploymentKey{ServiceKey: key, ID: strings.TrimPrefix(id, "ecs-svc/")}
}

func parseTerraformDeploymentKey(ctx context.Context, arn string) (terraformDeploymentKey, *awswire.Error) {
	scope, path, rejected := resourceID(ctx, arn, "service-deployment")
	parts := strings.Split(path, "/")
	if rejected != nil || !strings.HasPrefix(arn, "arn:") || len(parts) != 3 || !resourceName.MatchString(parts[0]) || !resourceName.MatchString(parts[1]) {
		return terraformDeploymentKey{}, failure("InvalidParameterException", "The ServiceDeployment ARN is invalid.")
	}
	if _, err := strconv.ParseUint(parts[2], 10, 64); err != nil || strings.HasPrefix(parts[2], "+") {
		return terraformDeploymentKey{}, failure("InvalidParameterException", "The ServiceDeployment ARN is invalid.")
	}
	return terraformDeploymentKey{ServiceKey: ServiceKey{ClusterKey: ClusterKey{Scope: scope, Name: parts[0]}, ServiceName: parts[1]}, ID: parts[2]}, nil
}

// terraformServiceDeployment projects native controller state, not task counts
// or the passage of time. Only the controller's healthy rollout completion can
// produce SUCCESSFUL. A circuit-breaker FAILED rollout is terminal STOPPED.
func terraformServiceDeployment(record ServiceRecord, deployment ServiceDeployment) api.ServiceDeployment {
	key := terraformDeploymentID(record.Key, value(deployment.Data.Id))
	revision := deploymentRevisionKey(record.Key, value(deployment.Data.Id))
	status := api.ServiceDeploymentStatusIN_PROGRESS
	switch value(deployment.Data.RolloutState) {
	case "COMPLETED":
		status = api.ServiceDeploymentStatusSUCCESSFUL
	case "FAILED":
		status = api.ServiceDeploymentStatusSTOPPED
	}
	out := api.ServiceDeployment{
		ServiceDeploymentArn: new(api.String(key.ARN())), ServiceArn: new(api.String(record.Key.ARN())),
		ClusterArn: new(api.String(record.Key.ClusterKey.ARN())), CreatedAt: cloneTerraformDeploymentMember(deployment.Data.CreatedAt),
		StartedAt: cloneTerraformDeploymentMember(deployment.Data.CreatedAt), UpdatedAt: cloneTerraformDeploymentMember(deployment.Data.UpdatedAt),
		Status: new(status), StatusReason: cloneTerraformDeploymentMember(deployment.Data.RolloutStateReason),
		TargetServiceRevision: &api.ServiceRevisionSummary{
			Arn: new(api.String(revision.ARN())), RequestedTaskCount: cloneTerraformDeploymentMember(deployment.Data.DesiredCount),
			RunningTaskCount: cloneTerraformDeploymentMember(deployment.Data.RunningCount), PendingTaskCount: cloneTerraformDeploymentMember(deployment.Data.PendingCount),
		},
	}
	if status != api.ServiceDeploymentStatusIN_PROGRESS && !deployment.FinishedAt.IsZero() {
		out.FinishedAt = new(deployment.FinishedAt)
		if status == api.ServiceDeploymentStatusSTOPPED {
			out.StoppedAt = new(deployment.FinishedAt)
		}
	}
	return out
}

// Retired projections contain only the public read snapshot; execution settings
// and task-definition ownership remain with the existing immutable revisions.
func cloneTerraformServiceDeployments(in api.ServiceDeployments) api.ServiceDeployments {
	if in == nil {
		return nil
	}
	out := make(api.ServiceDeployments, len(in))
	for i, deployment := range in {
		out[i] = cloneTerraformServiceDeployment(deployment)
	}
	return out
}

func cloneTerraformDeploymentMember[T any](in *T) *T {
	if in == nil {
		return nil
	}
	return new(*in)
}

func cloneTerraformServiceDeployment(in api.ServiceDeployment) api.ServiceDeployment {
	in.ServiceDeploymentArn = cloneTerraformDeploymentMember(in.ServiceDeploymentArn)
	in.ServiceArn = cloneTerraformDeploymentMember(in.ServiceArn)
	in.ClusterArn = cloneTerraformDeploymentMember(in.ClusterArn)
	in.CreatedAt = cloneTerraformDeploymentMember(in.CreatedAt)
	in.StartedAt = cloneTerraformDeploymentMember(in.StartedAt)
	in.UpdatedAt = cloneTerraformDeploymentMember(in.UpdatedAt)
	in.FinishedAt = cloneTerraformDeploymentMember(in.FinishedAt)
	in.StoppedAt = cloneTerraformDeploymentMember(in.StoppedAt)
	in.Status = cloneTerraformDeploymentMember(in.Status)
	in.StatusReason = cloneTerraformDeploymentMember(in.StatusReason)
	if in.TargetServiceRevision != nil {
		revision := *in.TargetServiceRevision
		revision.Arn = cloneTerraformDeploymentMember(revision.Arn)
		revision.RequestedTaskCount = cloneTerraformDeploymentMember(revision.RequestedTaskCount)
		revision.RunningTaskCount = cloneTerraformDeploymentMember(revision.RunningTaskCount)
		revision.PendingTaskCount = cloneTerraformDeploymentMember(revision.PendingTaskCount)
		in.TargetServiceRevision = &revision
	}
	return in
}

func terraformDeploymentBrief(deployment api.ServiceDeployment) api.ServiceDeploymentBrief {
	return api.ServiceDeploymentBrief{
		ServiceDeploymentArn: deployment.ServiceDeploymentArn, ServiceArn: deployment.ServiceArn, ClusterArn: deployment.ClusterArn,
		CreatedAt: deployment.CreatedAt, StartedAt: deployment.StartedAt, FinishedAt: deployment.FinishedAt,
		Status: deployment.Status, StatusReason: deployment.StatusReason, TargetServiceRevisionArn: deployment.TargetServiceRevision.Arn,
	}
}

func terraformDeploymentStatusValid(status api.ServiceDeploymentStatus) bool {
	switch status {
	case api.ServiceDeploymentStatusIN_PROGRESS, api.ServiceDeploymentStatusPENDING,
		api.ServiceDeploymentStatusROLLBACK_FAILED, api.ServiceDeploymentStatusROLLBACK_IN_PROGRESS,
		api.ServiceDeploymentStatusROLLBACK_REQUESTED, api.ServiceDeploymentStatusROLLBACK_SUCCESSFUL,
		api.ServiceDeploymentStatusSTOPPED, api.ServiceDeploymentStatusSTOP_REQUESTED, api.ServiceDeploymentStatusSUCCESSFUL:
		return true
	default:
		return false
	}
}

func terraformDeploymentTime(timestamp *api.Timestamp) string {
	if timestamp == nil {
		return ""
	}
	return timestamp.UTC().Format(time.RFC3339Nano)
}

func (s *Service) listServiceDeployments(ctx context.Context, tx Transaction, in *api.ListServiceDeploymentsInput) (*api.ListServiceDeploymentsOutput, error) {
	cluster, err := taskCluster(ctx, tx, value(in.Cluster))
	if err != nil {
		return nil, err
	}
	key, rejected := serviceKey(ctx, cluster.Key, value(in.Service))
	if rejected != nil {
		return nil, rejected
	}
	tags, err := tagsFor(tx, key.Scope, key.ARN())
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "ListServiceDeployments", key.ARN(), tags, map[string][]string{"ecs:cluster": {cluster.Key.ARN()}, "ecs:service": {key.ARN()}}); err != nil {
		return nil, err
	}
	record, err := tx.Service(key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ServiceNotFoundException", "Service not found.")
	}
	if err != nil {
		return nil, err
	}
	if value(record.Data.Status) == "INACTIVE" {
		return nil, failure("InvalidParameterException", "Cannot call ListServiceDeployments for a service that is INACTIVE")
	}
	limit, rejected := pageSize(in.MaxResults)
	if rejected != nil {
		return nil, rejected
	}
	statuses := slices.Clone(in.Status)
	for _, status := range statuses {
		if !terraformDeploymentStatusValid(status) {
			return nil, failure("InvalidParameterException", "Invalid service deployment status.")
		}
	}
	slices.Sort(statuses)
	statuses = slices.Compact(statuses)
	var afterTime, beforeTime *api.Timestamp
	if in.CreatedAt != nil {
		afterTime, beforeTime = in.CreatedAt.After, in.CreatedAt.Before
		if afterTime != nil && beforeTime != nil && afterTime.After(*beforeTime) {
			return nil, failure("InvalidParameterException", "createdAt.after must not be later than createdAt.before.")
		}
	}
	statusParts := make([]string, len(statuses))
	for i, status := range statuses {
		statusParts[i] = string(status)
	}
	identity := collection(key.Scope, "service-deployments", key.Name, key.ServiceName, terraformDeploymentTime(record.Data.CreatedAt), terraformDeploymentTime(afterTime), terraformDeploymentTime(beforeTime), strings.Join(statusParts, ","))
	after, rejected := page(in.NextToken, identity)
	if rejected != nil {
		return nil, rejected
	}
	out := &api.ListServiceDeploymentsOutput{ServiceDeployments: api.ServiceDeploymentsBrief{}}
	appendDeployment := func(deployment api.ServiceDeployment) {
		if value(deployment.ServiceDeploymentArn) <= after || len(statuses) > 0 && !slices.Contains(statuses, *deployment.Status) {
			return
		}
		if afterTime != nil && (deployment.CreatedAt == nil || !deployment.CreatedAt.After(*afterTime)) || beforeTime != nil && (deployment.CreatedAt == nil || !deployment.CreatedAt.Before(*beforeTime)) {
			return
		}
		out.ServiceDeployments = append(out.ServiceDeployments, terraformDeploymentBrief(deployment))
	}
	for _, deployment := range record.Deployments {
		appendDeployment(terraformServiceDeployment(record, deployment))
	}
	for _, deployment := range record.DeploymentHistory {
		appendDeployment(deployment)
	}
	// ARN keysets are independent of slice order and mutable rollout statuses;
	// insertion or retirement between pages cannot shift an offset cursor.
	slices.SortFunc(out.ServiceDeployments, func(a, b api.ServiceDeploymentBrief) int {
		return strings.Compare(value(a.ServiceDeploymentArn), value(b.ServiceDeploymentArn))
	})
	if len(out.ServiceDeployments) > limit {
		out.ServiceDeployments = out.ServiceDeployments[:limit]
		out.NextToken = nextPage(identity, value(out.ServiceDeployments[limit-1].ServiceDeploymentArn))
	}
	return out, nil
}

func (s *Service) describeServiceDeployments(ctx context.Context, tx Transaction, in *api.DescribeServiceDeploymentsInput) (*api.DescribeServiceDeploymentsOutput, error) {
	if len(in.ServiceDeploymentArns) == 0 || len(in.ServiceDeploymentArns) > 20 {
		return nil, failure("InvalidParameterException", "serviceDeploymentArns must contain between 1 and 20 entries.")
	}
	keys := make([]terraformDeploymentKey, len(in.ServiceDeploymentArns))
	for i, arn := range in.ServiceDeploymentArns {
		key, rejected := parseTerraformDeploymentKey(ctx, string(arn))
		if rejected != nil {
			return nil, rejected
		}
		if i != 0 && key.ServiceKey != keys[0].ServiceKey {
			return nil, failure("InvalidParameterException", "Cross service requests are not allowed. All requested service deployments must be for a single service")
		}
		keys[i] = key
	}
	owner := keys[0].ServiceKey
	tags, err := tagsFor(tx, owner.Scope, owner.ARN())
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := s.authorize(ctx, "DescribeServiceDeployments", key.ARN(), tags, map[string][]string{"ecs:cluster": {owner.ClusterKey.ARN()}, "ecs:service": {owner.ARN()}}); err != nil {
			return nil, err
		}
	}
	if _, err := taskCluster(ctx, tx, owner.ClusterKey.ARN()); err != nil {
		return nil, err
	}
	record, err := tx.Service(owner)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ServiceNotFoundException", "Service not found.")
	}
	if err != nil {
		return nil, err
	}
	if value(record.Data.Status) == "INACTIVE" {
		return nil, failure("InvalidParameterException", "Cannot call DescribeServiceDeployments for a service that is INACTIVE")
	}
	out := &api.DescribeServiceDeploymentsOutput{ServiceDeployments: api.ServiceDeployments{}, Failures: api.Failures{}}
	seen := make(map[terraformDeploymentKey]bool, len(keys))
	for _, key := range keys {
		var result api.ServiceDeployment
		found := false
		for _, deployment := range record.Deployments {
			if terraformDeploymentID(owner, value(deployment.Data.Id)) == key {
				result = terraformServiceDeployment(record, deployment)
				found = true
				break
			}
		}
		if !found {
			for _, deployment := range record.DeploymentHistory {
				if value(deployment.ServiceDeploymentArn) == key.ARN() {
					result = cloneTerraformServiceDeployment(deployment)
					found = true
					break
				}
			}
		}
		if !found {
			out.Failures = append(out.Failures, api.Failure{Arn: new(api.String(key.ARN())), Reason: new(api.String("MISSING"))})
			continue
		}
		if seen[key] {
			return nil, failure("ServerException", "Service Unavailable. Please try again later.", 500)
		}
		seen[key] = true
		out.ServiceDeployments = append(out.ServiceDeployments, result)
	}
	return out, nil
}
