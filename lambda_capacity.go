package stackd

import (
	"context"
	"errors"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/compute/lambda/managed"
	"stackd/internal/integrations"
	"stackd/internal/services/iam"
	"stackd/internal/services/lambda"
)

// LambdaManagedCapacityConfig selects an operator-prepared EC2 guest and its
// installed runtime images. The AMI must contain the official SSM agent,
// stackd-lambda-agent and Docker; no host execution substitutes for that guest.
type LambdaManagedCapacityConfig = integrations.LambdaCapacityConfig
type LambdaManagedImage = managed.Image

type lambdaCapacityRoleUsage struct{ service *lambda.Service }

func (u lambdaCapacityRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return u.service.WithCapacityRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, resources []string) error {
		slices.Sort(resources)
		var usage []iam.ServiceLinkedRoleUsage
		for _, resource := range resources {
			parsed, err := arn.Parse(resource)
			if err != nil {
				return err
			}
			if len(usage) == 0 || usage[len(usage)-1].Region != parsed.Region {
				usage = append(usage, iam.ServiceLinkedRoleUsage{Region: parsed.Region})
			}
			last := &usage[len(usage)-1]
			last.ResourceARNs = append(last.ResourceARNs, resource)
		}
		return fn(ctx, usage)
	})
}

func registerLambdaCapacityRoleUsage(identity *iam.Service, functions *lambda.Service) error {
	found := false
	for _, template := range identity.ServiceLinkedRoleTemplates() {
		if template.ServiceName != "lambda.amazonaws.com" {
			continue
		}
		if err := identity.RegisterServiceLinkedRole(template, lambdaCapacityRoleUsage{functions}); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return errors.New("lambda managed capacity service-linked role definition is missing")
	}
	return nil
}
