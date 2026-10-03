package iam

import (
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/iam/managed"
)

// AWS-owned policy documents are immutable catalogue data. The account working
// set materializes only referenced policies; usage counters derive from local
// identity records and are never persisted as copies of AWS policy documents.
func installAWSManagedPolicies(a *account, partition string) {
	install := func(arn string) *policy {
		if p := a.policies[arn]; p != nil {
			return p
		}
		p, ok := lookupAWSManagedPolicy(partition, arn)
		if !ok {
			return nil
		}
		a.policies[arn] = &p
		return &p
	}
	addIdentity := func(p identityPolicies, b *boundary) {
		for arn := range p.Attached {
			if isAWSManagedPolicyARN(arn) {
				if p := install(arn); p != nil {
					p.AttachmentCount++
				}
			}
		}
		if b != nil && isAWSManagedPolicyARN(b.PermissionsBoundaryArn) {
			if p := install(b.PermissionsBoundaryArn); p != nil {
				p.PermissionsBoundaryUsageCount++
			}
		}
	}
	for _, u := range a.users {
		addIdentity(u.IdentityPolicies, u.PermissionsBoundary)
	}
	for _, g := range a.groups {
		addIdentity(g.IdentityPolicies, nil)
	}
	for _, r := range a.roles {
		addIdentity(r.IdentityPolicies, r.PermissionsBoundary)
	}
}

func isAWSManagedPolicyARN(arn string) bool {
	parts := strings.SplitN(arn, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[2] == "iam" && parts[3] == "" && parts[4] == "aws" && strings.HasPrefix(parts[5], "policy/")
}

func lookupAWSManagedPolicy(partition, arn string) (ManagedPolicy, bool) {
	// Customer references must go directly to their typed repository. Loading
	// the immutable AWS catalogue here is expensive and cannot resolve them.
	prefix := "arn:" + partition + ":iam::aws:policy/"
	if partition == "" || !strings.HasPrefix(arn, prefix) || len(arn) == len(prefix) {
		return ManagedPolicy{}, false
	}
	p, ok := managed.Lookup(partition, arn)
	if !ok {
		return ManagedPolicy{}, false
	}
	return cataloguePolicy(p), true
}

func cataloguePolicy(p managed.Policy) ManagedPolicy {
	result := ManagedPolicy{PolicyName: p.Name, PolicyId: p.ID, Arn: p.ARN, Path: p.Path, DefaultVersionId: p.DefaultVersion, IsAttachable: p.Attachable, Description: p.Description, CreateDate: p.Created, UpdateDate: p.Updated, Versions: make(map[string]*policyVersion, len(p.Versions))}
	for _, v := range p.Versions {
		result.Versions[v.ID] = &policyVersion{VersionId: v.ID, Document: v.Document, IsDefaultVersion: v.Default, CreateDate: v.Created}
	}
	return result
}

func managedPolicyMutationError(arn, operation string) *awswire.Error {
	if !isAWSManagedPolicyARN(arn) {
		return nil
	}
	message := map[string]string{
		"DeletePolicy":            "Cannot delete policies outside your own account.",
		"CreatePolicyVersion":     "Cannot create versions for policies outside your own account.",
		"SetDefaultPolicyVersion": "Cannot update policies outside your own account.",
		"DeletePolicyVersion":     "Cannot delete policy versions for policies outside your own account.",
	}[operation]
	return &awswire.Error{Code: "AccessDenied", StatusCode: 403, Message: message}
}

func policyAttachmentError(p *policy, kind string) *awswire.Error {
	// AWS marks reserved policies IsAttachable=true because AWS services can
	// attach them. Customer IAM attachment/boundary APIs reject these domains.
	if isAWSManagedPolicyARN(p.Arn) && (p.Path == "/aws-service-role/" || p.Path == "/root-task/") {
		return &awswire.Error{Code: "PolicyNotAttachable", StatusCode: 400, Message: "Cannot attach AWS reserved policy to an IAM " + strings.ToLower(kind) + "."}
	}
	if !p.IsAttachable {
		return &awswire.Error{Code: "PolicyNotAttachable", StatusCode: 400, Message: "The policy is not attachable."}
	}
	return nil
}

func localPolicyCount(a *account) int {
	n := 0
	for arn := range a.policies {
		if !isAWSManagedPolicyARN(arn) {
			n++
		}
	}
	return n
}

func unavailableManagedCatalogue(partition string) *awswire.Error {
	// TODO: Comeback capture authoritative AWS China and GovCloud managed-policy catalogues with partition-specific credentials; commercial policy ARNs/documents cannot establish their contents.
	return &awswire.Error{Code: "NotImplemented", StatusCode: 501, Message: "The authoritative AWS managed policy catalogue for partition " + partition + " has not been captured."}
}
