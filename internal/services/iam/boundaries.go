package iam

import (
	"context"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func resolveBoundary(a *account, arn, kind string) (*boundary, *awswire.Error) {
	if arn == "" {
		return nil, nil
	}
	p, err := findPolicyARN(a, arn)
	if err != nil {
		return nil, err
	}
	if err := policyAttachmentError(p, kind); err != nil {
		return nil, err
	}
	return &boundary{PermissionsBoundaryType: "Policy", PermissionsBoundaryArn: arn}, nil
}

func boundaryTarget(a *account, kind, name string) (**boundary, *awswire.Error) {
	if kind == "User" {
		u, err := findUser(a, name)
		if err != nil {
			return nil, err
		}
		return &u.PermissionsBoundary, nil
	}
	r, err := findRole(a, name)
	if err != nil {
		return nil, err
	}
	return &r.PermissionsBoundary, nil
}

func putBoundary(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	request, _ := awsapi.FromContext(ctx)
	var kind, targetName, arn string
	switch in := request.Input.(type) {
	case *iamapi.PutUserPermissionsBoundaryInput:
		kind, targetName = "User", inputString(in.UserName)
		arn = inputString(in.PermissionsBoundary)
	case *iamapi.PutRolePermissionsBoundaryInput:
		kind, targetName = "Role", inputString(in.RoleName)
		arn = inputString(in.PermissionsBoundary)
	default:
		return nil, requestBindingFailure()
	}
	target, err := boundaryTarget(a, kind, targetName)
	if err != nil {
		return nil, err
	}
	b, err := resolveBoundary(a, arn, kind)
	if err != nil {
		return nil, err
	}
	if *target != nil {
		a.policies[(*target).PermissionsBoundaryArn].PermissionsBoundaryUsageCount--
	}
	*target = b
	a.policies[b.PermissionsBoundaryArn].PermissionsBoundaryUsageCount++
	return &iamapi.Unit{}, nil
}

func deleteBoundary(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	request, _ := awsapi.FromContext(ctx)
	var kind, targetName string
	switch in := request.Input.(type) {
	case *iamapi.DeleteUserPermissionsBoundaryInput:
		kind, targetName = "User", inputString(in.UserName)
	case *iamapi.DeleteRolePermissionsBoundaryInput:
		kind, targetName = "Role", inputString(in.RoleName)
	default:
		return nil, requestBindingFailure()
	}
	target, err := boundaryTarget(a, kind, targetName)
	if err != nil {
		return nil, err
	}
	if *target == nil {
		return nil, missing("permissions boundary", targetName)
	}
	a.policies[(*target).PermissionsBoundaryArn].PermissionsBoundaryUsageCount--
	*target = nil
	return &iamapi.Unit{}, nil
}
