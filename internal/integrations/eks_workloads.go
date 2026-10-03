package integrations

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/awsapi"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/ec2"
	"stackd/internal/services/eks"
)

// EKSWorkloadRoles reads the current IAM and EC2 owners in the caller transaction.
// The pod execution role authorizes infrastructure, never credentials in a pod.
type EKSWorkloadRoles struct {
	Roles ServiceRoles
	EC2   ec2.Repository
	ECR   interface {
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	}
	RegistryEndpoint string
}

func (a EKSWorkloadRoles) ValidateFargateExecutionRole(ctx context.Context, arn, profileARN string) (string, error) {
	if a.Roles.IAM == nil || a.Roles.Authorizer == nil {
		return "", errors.New("fargate IAM authority is unavailable")
	}
	ctx = awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "eks-fargate-pods.amazonaws.com", SourceARN: profileARN, Type: "AWSService"})
	var id string
	err := a.Roles.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, err := a.Roles.IAM.RoleForAssumption(ctx, arn)
		if err != nil {
			return err
		}
		if rejected := a.Roles.trust(ctx, role, identity.RoleSessionSpec{SessionName: "EKSFargate"}, now, ""); rejected != nil {
			return rejected
		}
		id = role.ID
		return nil
	})
	return id, err
}
func (a EKSWorkloadRoles) ValidateFargateSubnets(ctx context.Context, k eks.Key, vpc string, subnets []string) error {
	if a.EC2 == nil {
		return errors.New("fargate EC2 network authority is unavailable")
	}
	if len(subnets) == 0 {
		return eksNetworkInvalid("Fargate requires private subnets.")
	}
	return a.EC2.View(ctx, func(tx ec2.Reader) error {
		scope := ec2.Scope{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region}
		tables, err := tx.RouteTables(scope)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, id := range subnets {
			if seen[id] {
				return eksNetworkInvalid("Fargate subnets must not be duplicated.")
			}
			seen[id] = true
			subnet, err := tx.Subnet(ec2.ResourceKey{Scope: scope, ID: id})
			if err != nil {
				return err
			}
			if subnet.Data.VpcId == nil || string(*subnet.Data.VpcId) != vpc {
				return eksNetworkInvalid("Fargate subnets must belong to the cluster VPC.")
			}
			explicit := -1
			main := -1
			for i, table := range tables {
				if table.Data.VpcId == nil || string(*table.Data.VpcId) != vpc {
					continue
				}
				for _, association := range table.Data.Associations {
					if association.SubnetId != nil && string(*association.SubnetId) == id {
						explicit = i
					}
					if association.Main != nil && bool(*association.Main) {
						main = i
					}
				}
			}
			chosen := explicit
			if chosen < 0 {
				chosen = main
			}
			if chosen < 0 {
				return eksNetworkInvalid("Fargate subnet has no route table.")
			}
			for _, route := range tables[chosen].Data.Routes {
				if route.GatewayId != nil && strings.HasPrefix(string(*route.GatewayId), "igw-") {
					return eksNetworkInvalid("Fargate requires private subnets without a direct route to an Internet Gateway.")
				}
			}
		}
		return nil
	})
}

var _ eks.WorkloadRoles = EKSWorkloadRoles{}
