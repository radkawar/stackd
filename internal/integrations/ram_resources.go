package integrations

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awswire"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/ec2"
	"stackd/internal/services/ram"
	"stackd/internal/services/ssm"
)

// RAMResources routes to real owners; it cannot accept a resource merely because
// its ARN matches an AWS resource type. Missing owners are explicitly unsupported.
type RAMResources struct {
	SSM       *ssm.Service
	EC2       *ec2.Service
	CodeBuild *codebuild.Service
}

func (a RAMResources) ResolveResource(ctx context.Context, resource string) (ram.ResourceIdentity, error) {
	parsed, err := arn.Parse(resource)
	if err != nil {
		return ram.ResourceIdentity{}, ram.ErrUnsupportedResource
	}
	identity := ram.ResourceIdentity{ARN: resource, Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region}
	switch {
	case parsed.Service == "ssm" && strings.HasPrefix(parsed.Resource, "parameter/") && a.SSM != nil:
		current, err := a.SSM.ResolveShareableParameter(ctx, resource)
		if errors.Is(err, ssm.ErrNotFound) {
			return identity, ram.ErrNotFound
		}
		if err != nil {
			var rejected *awswire.Error
			if errors.As(err, &rejected) && rejected.Code == "ResourcePolicyInvalidParameterException" {
				return identity, ram.ErrUnsupportedResource
			}
			return identity, err
		}
		identity.ARN, identity.ResourceType = current.ARN, "ssm:Parameter"
		identity.SupportsIAMPrincipals = true
	case parsed.Service == "ec2" && strings.HasPrefix(parsed.Resource, "subnet/") && a.EC2 != nil:
		current, err := a.EC2.ResolveShareableSubnet(ctx, resource)
		if errors.Is(err, ec2.ErrNotFound) {
			return identity, ram.ErrNotFound
		}
		if errors.Is(err, ec2.ErrSubnetNotShareable) {
			return identity, ram.ErrUnsupportedResource
		}
		if err != nil {
			return identity, err
		}
		identity.ARN, identity.ResourceType = current.ARN, "ec2:Subnet"
		identity.OrganizationOnly = true
	case parsed.Service == "codebuild" && strings.HasPrefix(parsed.Resource, "project/") && a.CodeBuild != nil:
		current, err := a.CodeBuild.ResolveSharedProject(ctx, resource)
		if errors.Is(err, codebuild.ErrNotFound) {
			return identity, ram.ErrNotFound
		}
		if err != nil {
			return identity, err
		}
		identity.ARN, identity.ResourceType = current.ARN, "codebuild:Project"
		identity.SupportsIAMPrincipals = true
	default:
		// Glue RAM shares require Lake Formation's grant/regrant owner; report
		// groups, capacity reservations and other types need their actual owners.
		return identity, ram.ErrUnsupportedResource
	}
	return identity, nil
}

func (a RAMResources) AuthorizeResourceSharing(ctx context.Context, resource string) error {
	parsed, err := arn.Parse(resource)
	if err != nil {
		return ram.ErrUnsupportedResource
	}
	switch {
	case parsed.Service == "ssm" && strings.HasPrefix(parsed.Resource, "parameter/") && a.SSM != nil:
		return a.SSM.AuthorizeParameterSharing(ctx, resource)
	case parsed.Service == "ec2" && strings.HasPrefix(parsed.Resource, "subnet/") && a.EC2 != nil:
		return a.EC2.AuthorizeSubnetSharing(ctx, resource)
	case parsed.Service == "codebuild" && strings.HasPrefix(parsed.Resource, "project/") && a.CodeBuild != nil:
		return a.CodeBuild.AuthorizeResourceSharing(ctx, resource)
	default:
		return ram.ErrUnsupportedResource
	}
}

func (a RAMResources) RemoveResourcePolicy(ctx context.Context, resource, id, principal string) error {
	parsed, err := arn.Parse(resource)
	if err == nil && parsed.Service == "ssm" && strings.HasPrefix(parsed.Resource, "parameter/") && a.SSM != nil {
		return a.SSM.RemoveParameterResourcePolicy(ctx, resource, id, principal)
	}
	return ram.ErrUnsupportedResource
}
