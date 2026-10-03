package iam

import (
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/iam/managed"
)

// AWS-owned policies and commercial role templates expose IAM's service account
// to conditions, rather than the public ARN alias "aws". Resolve it identically
// for direct operations and the dependent template read inside AcquireRole.
func awsManagedResourceAccount(partition, arn string) (string, *awswire.Error) {
	if !isAWSManagedPolicyARN(arn) && (partition != "aws" || !strings.HasPrefix(arn, "arn:aws:iam::aws:role-template/")) {
		return "", nil
	}
	owner, ok := managed.ResourceAccount(partition)
	if !ok {
		return "", unavailableManagedCatalogue(partition)
	}
	return owner, nil
}
