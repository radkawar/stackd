package sqs

import (
	"context"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

type queueOwnerKey struct{}
type queuePolicyOwnerKey struct{}

// WithCloudFormationPolicyOwner binds a policy slot independently of the queue.
func WithCloudFormationPolicyOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, queuePolicyOwnerKey{}, owner)
}

func queuePolicyOwner(ctx context.Context) string {
	owner, _ := ctx.Value(queuePolicyOwnerKey{}).(string)
	return owner
}

// QueueClaims are private native authorities, never protocol output.
type QueueClaims struct{ CreationOwner, PolicyOwner string }

// WithCloudFormationOwner binds internal resource commands to an exact creation
// incarnation. Public queue tags neither grant nor change this authority.
func WithCloudFormationOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, queueOwnerKey{}, owner)
}

func queueOwner(ctx context.Context) string {
	owner, _ := ctx.Value(queueOwnerKey{}).(string)
	return owner
}

func checkQueueOwner(ctx context.Context, q *queue) *awswire.Error {
	if owner := queueOwner(ctx); owner != "" && owner != q.creationOwner {
		return failure("AccessDenied", "The queue is not owned by this resource incarnation.")
	}
	return nil
}

// CloudFormationQueueOwner observes private creation authority under the same
// current IAM and resource-policy checks as GetQueueUrl. Absence and failures
// remain distinct; the caller must never infer ownership from public tags.
func (s *Service) CloudFormationQueueOwner(ctx context.Context, name string) (string, error) {
	claims, err := s.queueClaims(ctx, name, "GetQueueUrl")
	return claims.CreationOwner, err
}

// CloudFormationQueueClaims observes private queue and policy authority.
func (s *Service) CloudFormationQueueClaims(ctx context.Context, name string) (QueueClaims, error) {
	return s.queueClaims(ctx, name, "GetQueueAttributes")
}

func (s *Service) queueClaims(ctx context.Context, name, action string) (QueueClaims, error) {
	var claims QueueClaims
	err := s.authorizedCommand(ctx, nil, func(ctx context.Context) ([]authorization.Request, *awswire.Error) {
		m := awsctx.FromContext(ctx)
		q := s.lookupQueue(queueKey{partition: m.Partition, account: m.AccountID, region: m.Region, name: name})
		if q == nil {
			return nil, failure("QueueDoesNotExist", "The specified queue does not exist.")
		}
		claims = QueueClaims{CreationOwner: q.creationOwner, PolicyOwner: q.policyOwner}
		permission := queuePermission(q, action)
		if m.SessionType == string(identity.SessionTypeAssumeRoot) {
			permission.ResourcePolicies = nil
		}
		return []authorization.Request{permission}, nil
	}, func(context.Context) *awswire.Error { return nil })
	if err != nil {
		return QueueClaims{}, err
	}
	return claims, nil
}
