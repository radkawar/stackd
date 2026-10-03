package iam

import (
	"context"
	"time"
)

// ServiceLinkedRoleDeletion is a persistent deletion job. RoleID, not its
// reusable name or ARN, identifies the resource this job may remove. Terminal
// jobs remain readable after the role is deleted.
type ServiceLinkedRoleDeletion struct {
	ID, RoleID, RoleARN, RoleName, ServiceName, Status, FailureReason string
	CreatedAt, UpdatedAt                                              time.Time
	Usage                                                             []ServiceLinkedRoleUsage
}

// ServiceLinkedRoleUsage identifies dependent resources in one AWS region.
type ServiceLinkedRoleUsage struct {
	Region       string
	ResourceARNs []string
}

// ServiceLinkedRoleReference identifies one immutable, service-owned role.
type ServiceLinkedRoleReference struct {
	Scope                      Scope
	ID, ARN, Name, ServiceName string
}

// ServiceLinkedRoleUsageProvider owns the linked service's deletion check. It
// must keep usage stable while fn runs, including excluding new dependencies.
// Call fn exactly once on success, synchronously, and do not retain its values.
// The callback joins its supplied context when acquiring an IAM transaction.
// Local providers may borrow a shared transaction to keep their dependencies
// and IAM deletion atomic. External providers must use service -> IAM lock
// ordering for resource creation as well as deletion. Neither the callback
// context nor usage records may outlive the callback or be used concurrently.
// Honor context cancellation promptly; IAM Close cancels and joins these
// external checks and cannot interrupt a provider that ignores its context.
type ServiceLinkedRoleUsageProvider interface {
	WithServiceLinkedRoleUsage(context.Context, ServiceLinkedRoleReference, func(context.Context, []ServiceLinkedRoleUsage) error) error
}

// ServiceLinkedRoleInUseError reports a service-owned dependency that has no
// resource ARN, such as an account feature. A provider may return it without
// calling the completion callback. Unexpected errors retain the generic
// unavailable-usage failure; this error preserves the dependency's diagnosis.
type ServiceLinkedRoleInUseError struct{ Reason string }

func (e *ServiceLinkedRoleInUseError) Error() string {
	return "The service-linked role is in use: " + e.Reason
}

const (
	serviceLinkedNotStarted = "NOT_STARTED"
	serviceLinkedInProgress = "IN_PROGRESS"
	serviceLinkedFailed     = "FAILED"
	serviceLinkedSucceeded  = "SUCCEEDED"
)

func serviceLinkedPending(status string) bool {
	return status == serviceLinkedNotStarted || status == serviceLinkedInProgress
}
