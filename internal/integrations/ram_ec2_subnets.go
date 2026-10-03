package integrations

import (
	"context"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/services/ec2"
	"stackd/internal/services/ram"
)

// RAMSharedSubnets delegates live access to RAM while EC2 retains all network,
// allocation, resource identity and participant ownership authority.
type RAMSharedSubnets struct{ RAM *ram.Service }

var _ ec2.SharedSubnetAccess = RAMSharedSubnets{}

func (a RAMSharedSubnets) SharedSubnets(ctx context.Context, scope ec2.Scope, action string) ([]ec2.SharedSubnetIdentity, error) {
	rows, err := a.RAM.SharedResources(ctx, ram.SharedResourcesQuery{Partition: scope.Partition, Region: scope.Region, AccountID: scope.AccountID, ResourceType: "ec2:Subnet", Action: action})
	if err != nil {
		return nil, err
	}
	out := make([]ec2.SharedSubnetIdentity, 0, len(rows))
	for _, row := range rows {
		_, id, ok := strings.Cut(row.ARN, ":subnet/")
		if !ok {
			continue
		}
		out = append(out, ec2.SharedSubnetIdentity{Key: ec2.ResourceKey{Scope: ec2.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: id}, ARN: row.ARN})
	}
	return out, nil
}

func (a RAMSharedSubnets) SubnetResourcePolicies(ctx context.Context, arn string) ([]authorization.BoundPolicy, error) {
	return a.RAM.ResourcePolicies(ctx, arn)
}

func (a RAMSharedSubnets) SubnetDeleted(ctx context.Context, arn string) error {
	return a.RAM.ResourceDeleted(ctx, arn)
}
