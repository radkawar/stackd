package kms

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

func (s *Service) bindGrantPrincipal(ctx context.Context, reference string) (string, string, *awswire.Error) {
	partition := scopeFor(ctx).partition
	if regionalEC2GrantPrincipal(reference, partition) || regionalECRGrantPrincipal(reference, partition) {
		return reference, "", nil
	}
	if len(reference) == 12 && strings.Trim(reference, "0123456789") == "" {
		return "arn:" + partition + ":iam::" + reference + ":root", "", nil
	}
	parts := strings.SplitN(reference, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && parts[1] == partition && parts[2] == "iam" && parts[3] == "" && len(parts[4]) == 12 && strings.Trim(parts[4], "0123456789") == "" && parts[5] == "root" {
		return reference, "", nil
	}
	resolver, ok := s.authorizer.(authorization.GrantPrincipalResolver)
	if !ok {
		return "", "", failure("UnsupportedOperationException", "IAM grant principal resolution is not configured.")
	}
	principal, err := resolver.ResolveGrantPrincipal(ctx, reference)
	if errors.Is(err, authorization.ErrInvalidPrincipal) {
		return "", "", failure("InvalidArnException", "ARN does not refer to a valid principal: "+reference)
	}
	if err != nil {
		return "", "", failure("KMSInternalException", "Unable to resolve grant principal.")
	}
	return principal.ARN, principal.ID, nil
}

// Regional EC2 consumers use the legacy principal fields, not the distinct
// GranteeServicePrincipal API. Other service names and partitions are uncaptured.
// TODO: Comeback capture and implement regional EC2 grants in other partitions.
func regionalEC2GrantPrincipal(reference, partition string) bool {
	return regionalGrantPrincipal(reference, partition, "ec2")
}

// ECR's documented CreateGrant records use the regional service in the legacy
// principal fields and constrain authority with the repository encryption context.
func regionalECRGrantPrincipal(reference, partition string) bool {
	return regionalGrantPrincipal(reference, partition, "ecr")
}

func regionalGrantPrincipal(reference, partition, service string) bool {
	if partition != "aws" {
		return false
	}
	region, ok := strings.CutPrefix(reference, service+".")
	if !ok {
		return false
	}
	region, ok = strings.CutSuffix(region, ".amazonaws.com")
	return ok && awscatalog.RegionPartition(region) == partition
}

func sameGrantPrincipal(arn, id, otherARN, otherID string) bool {
	if id != "" || otherID != "" {
		return id == otherID
	}
	return arn == otherARN
}

func (s *Service) renderGrantPrincipal(ctx context.Context, reference, id string) (string, *awswire.Error) {
	if id == "" {
		return reference, nil
	}
	resolver, ok := s.authorizer.(authorization.GrantPrincipalResolver)
	if !ok {
		return "", failure("KMSInternalException", "IAM grant principal resolution is not configured.")
	}
	principal, err := resolver.ResolveGrantPrincipal(ctx, id)
	if errors.Is(err, authorization.ErrInvalidPrincipal) {
		return id, nil
	}
	if err != nil {
		return "", failure("KMSInternalException", "Unable to resolve grant principal.")
	}
	return principal.ARN, nil
}
