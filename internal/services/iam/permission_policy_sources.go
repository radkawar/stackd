package iam

import (
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// permissionPolicySource retains the current document and its origin. Managed
// policies have an ARN; inline policies retain the owning identity. Boundaries,
// trust policies and session policies are separate policy types.
type permissionPolicySource struct {
	document, arn, name, ownerKind, ownerName string
}

type permissionPolicyOwner struct {
	kind, name string
	policies   IdentityPolicies
}

type permissionPolicyIdentity struct {
	arn, kind, name, id string
	boundary            *Boundary
	serviceLinked       bool
	owners              []permissionPolicyOwner
}

// resolvePermissionPolicyIdentity owns the user/group/role traversal shared by
// simulation and permission introspection. User policies precede inherited
// groups, whose names are sorted. Each consumer selects the policy types it uses.
func resolvePermissionPolicyIdentity(a *account, m awsctx.Metadata, arn string) (permissionPolicyIdentity, *awswire.Error) {
	kind, name, apiErr := contextKeySourceARN(arn)
	if apiErr != nil {
		return permissionPolicyIdentity{}, apiErr
	}
	parts := strings.SplitN(arn, ":", 6)
	if parts[1] != m.Partition || parts[4] != m.AccountID {
		return permissionPolicyIdentity{}, invalidInput("PolicySourceArn must identify an IAM user, group, or role in this account.")
	}
	return permissionPolicyIdentityByName(a, kind, name)
}

func permissionPolicyIdentityByName(a *account, kind, name string) (permissionPolicyIdentity, *awswire.Error) {
	result := permissionPolicyIdentity{kind: kind, name: name}
	switch kind {
	case "user":
		u := a.users[strings.ToLower(name)]
		if u == nil {
			return result, missing("user", name)
		}
		result.arn, result.name, result.id, result.boundary = u.Arn, u.UserName, u.UserId, u.PermissionsBoundary
		result.owners = append(result.owners, permissionPolicyOwner{kind, u.UserName, u.IdentityPolicies})
		for _, key := range sortedMapKeys(a.groups) {
			g := a.groups[key]
			if _, member := g.Members[strings.ToLower(u.UserName)]; member {
				result.owners = append(result.owners, permissionPolicyOwner{"group", g.GroupName, g.IdentityPolicies})
			}
		}
	case "group":
		g := a.groups[strings.ToLower(name)]
		if g == nil {
			return result, missing("group", name)
		}
		result.arn, result.name, result.id = g.Arn, g.GroupName, g.GroupId
		result.owners = append(result.owners, permissionPolicyOwner{kind, g.GroupName, g.IdentityPolicies})
	case "role":
		r := a.roles[strings.ToLower(name)]
		if r == nil {
			return result, missing("role", name)
		}
		result.arn, result.name, result.id, result.boundary = r.Arn, r.RoleName, r.RoleId, r.PermissionsBoundary
		result.serviceLinked = r.ServiceLinkedService != ""
		result.owners = append(result.owners, permissionPolicyOwner{kind, r.RoleName, r.IdentityPolicies})
	}
	return result, nil
}

func permissionPolicySources(a *account, owners []permissionPolicyOwner) ([]permissionPolicySource, *awswire.Error) {
	sources := make([]permissionPolicySource, 0)
	managed := make(map[string]bool)
	for _, owner := range owners {
		for _, name := range sortedMapKeys(owner.policies.Inline) {
			sources = append(sources, permissionPolicySource{document: owner.policies.Inline[name], name: name, ownerKind: owner.kind, ownerName: owner.name})
		}
		for _, arn := range sortedMapKeys(owner.policies.Attached) {
			if managed[arn] {
				continue
			}
			managed[arn] = true
			source, apiErr := managedPermissionPolicySource(a, arn)
			if apiErr != nil {
				return nil, apiErr
			}
			sources = append(sources, source)
		}
	}
	return sources, nil
}

func managedPermissionPolicySource(a *account, arn string) (permissionPolicySource, *awswire.Error) {
	document, err := currentPolicySnapshot(a, arn)
	if err != nil {
		return permissionPolicySource{}, &awswire.Error{Code: "ServiceFailure", Message: "Unable to load a principal policy.", StatusCode: 500}
	}
	stored := a.policies[arn]
	if stored == nil {
		managed, ok := lookupAWSManagedPolicy(a.partition, arn)
		if !ok {
			return permissionPolicySource{}, &awswire.Error{Code: "ServiceFailure", Message: "Unable to load policy metadata.", StatusCode: 500}
		}
		stored = &managed
	}
	return permissionPolicySource{document: document.Document, arn: arn, name: stored.PolicyName}, nil
}
