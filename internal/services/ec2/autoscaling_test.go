package ec2_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
)

func TestAutoScalingHandledDryRunKeepsConsumerTransactionUsable(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repository ec2.Repository
			if backend == "memory" {
				repository = ec2.NewMemoryRepository(nil)
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "dryrun.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				repository = sqlec2.New(db)
			}
			service := ec2.New(ec2.Config{Repository: repository})
			t.Cleanup(func() { service.Close() })
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
			model, _ := awscatalog.LookupService("ec2")
			command := func(ctx context.Context, action string, input any) (any, error) {
				op, _ := model.Operation(action)
				out, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
				if rejected != nil {
					return nil, rejected
				}
				return out, nil
			}
			var vpcID string
			err := repository.Update(ctx, func(tx ec2.Transaction) error {
				// EC2's own native DryRunOperation is expected admission success
				// for its ASG consumer; it must not poison that outer transaction.
				op, _ := model.Operation("DescribeSubnets")
				_, rejected := service.ExecuteCommand(tx.Context(), awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: &api.DescribeSubnetsRequest{DryRun: new(api.Boolean(true))}})
				if rejected == nil || rejected.Code != "DryRunOperation" {
					return fmt.Errorf("expected DryRunOperation, got %v", rejected)
				}
				out, err := command(tx.Context(), "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.83.0.0/16"))})
				if err != nil {
					return err
				}
				vpcID = string(*out.(*api.CreateVpcResult).Vpc.VpcId)
				return nil
			})
			if err != nil {
				t.Fatalf("handled dry run aborted the consumer transaction: %v", err)
			}
			out, err := command(ctx, "DescribeVpcs", &api.DescribeVpcsRequest{VpcIds: api.VpcIdStringList{api.VpcId(vpcID)}})
			if err != nil {
				t.Fatal(err)
			}
			vpcs := out.(*api.DescribeVpcsResult).Vpcs
			if len(vpcs) != 1 || string(*vpcs[0].VpcId) != vpcID || string(*vpcs[0].CidrBlock) != "10.83.0.0/16" {
				t.Fatalf("consumer's native VPC mutation did not commit: %#v", vpcs)
			}
		})
	}
}
