package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	cfnstore "stackd/storage/cloudformation"
)

// This interrupts only the CloudFormation progress commit after the real EC2
// deletion. The native owner is not mocked and its successful deletion remains
// committed, reproducing the recovery window before BeforeDeleted is retained.
type cfnReplacementCommitInterruption struct {
	cfnstore.Repository
	armed   *atomic.Bool
	deleted chan struct{}
}

func (r *cfnReplacementCommitInterruption) Update(ctx context.Context, fn func(cfnstore.Transaction) error) error {
	return r.Repository.Update(ctx, func(tx cfnstore.Transaction) error {
		if err := fn(tx); err != nil {
			return err
		}
		if !r.armed.Load() {
			return nil
		}
		op, found, err := tx.NextOperation()
		if err != nil || !found || op.Kind != "UPDATE" || op.Phase != "APPLY" || op.Cancel {
			return err
		}
		for _, step := range op.Steps {
			if step.BeforeDeleted && step.State == "BEFORE_DELETED" {
				select {
				case r.deleted <- struct{}{}:
				default:
				}
				return errors.New("interrupted delete-before-create progress commit")
			}
		}
		return nil
	})
}

func cfnAssociationReplacementTemplate(t *testing.T, table, queue string) string {
	t.Helper()
	ref := func(id string) map[string]any { return map[string]any{"Ref": id} }
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{
			"VPC":              map[string]any{"Type": "AWS::EC2::VPC", "Properties": map[string]any{"CidrBlock": "10.76.0.0/16"}},
			"Subnet":           map[string]any{"Type": "AWS::EC2::Subnet", "Properties": map[string]any{"VpcId": ref("VPC"), "CidrBlock": "10.76.1.0/24"}},
			"OriginalTable":    map[string]any{"Type": "AWS::EC2::RouteTable", "Properties": map[string]any{"VpcId": ref("VPC")}},
			"ReplacementTable": map[string]any{"Type": "AWS::EC2::RouteTable", "Properties": map[string]any{"VpcId": ref("VPC")}},
			"Association":      map[string]any{"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": map[string]any{"SubnetId": ref("Subnet"), "RouteTableId": ref(table)}},
			"Queue":            map[string]any{"Type": "AWS::SQS::Queue", "DependsOn": "Association", "Properties": map[string]any{"QueueName": queue}},
		},
		"Outputs": map[string]any{
			"Association":   map[string]any{"Value": ref("Association")},
			"Subnet":        map[string]any{"Value": ref("Subnet")},
			"OriginalTable": map[string]any{"Value": ref("OriginalTable")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// The dependent foreign queue forces rollback after an exclusive native
// association has already been replaced. A rollback must really re-associate
// the original route table, with a new incarnation, identity and output value.
func TestCloudFormationDeleteFirstReplacementRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, interrupted := range []bool{false, true} {
			name := backend + "/dependent-failure"
			if interrupted {
				name = backend + "/cancel-after-unretained-deletion"
			}
			t.Run(name, func(t *testing.T) {
				source := clock.NewManual(time.Date(2031, 6, 7, 8, 9, 10, 0, time.UTC))
				var armed atomic.Bool
				deleted := make(chan struct{}, 1)
				var repository cfnstore.Repository
				clients, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					repository = config.Storage.CloudFormation
					config.Storage.CloudFormation = &cfnReplacementCommitInterruption{Repository: repository, armed: &armed, deleted: deleted}
					return startPublicCloud(t, config)
				})
				cfn := func() *cloudformation.Client { return cloudFormationClient(clients, "us-east-1", "test", "test") }
				created, err := cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("exclusive-route-replacement"), TemplateBody: aws.String(cfnAssociationReplacementTemplate(t, "OriginalTable", "replacement-owned-queue"))})
				if err != nil {
					t.Fatal(err)
				}
				initial := cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
				outputs := func(stack cfntypes.Stack) map[string]string {
					values := map[string]string{}
					for _, output := range stack.Outputs {
						values[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
					}
					return values
				}
				before := outputs(initial)
				_, err = clients.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("replacement-foreign-queue")})
				if err != nil {
					t.Fatal(err)
				}
				armed.Store(interrupted)
				if _, err = cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(cfnAssociationReplacementTemplate(t, "ReplacementTable", "replacement-foreign-queue"))}); err != nil {
					t.Fatal(err)
				}
				if interrupted {
					select {
					case <-deleted:
					case <-time.After(15 * time.Second):
						t.Fatal("replacement never reached the native-deletion commit interruption")
					}
					if _, err := cfn().CancelUpdateStack(t.Context(), &cloudformation.CancelUpdateStackInput{StackName: created.StackId}); err != nil {
						t.Fatal(err)
					}
					armed.Store(false)
					clients = reopen()
				}
				rolledBack := cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusUpdateRollbackComplete)
				after := outputs(rolledBack)
				if before["Association"] == "" || after["Association"] == "" || after["Association"] == before["Association"] {
					t.Fatalf("rollback reused a deleted native association instead of restoring it: before=%v after=%v", before, after)
				}
				live, err := asgEC2(clients, "us-east-1").DescribeRouteTables(t.Context(), &ec2.DescribeRouteTablesInput{Filters: []ec2types.Filter{{Name: aws.String("association.subnet-id"), Values: []string{before["Subnet"]}}}})
				if err != nil {
					t.Fatal(err)
				}
				associations := 0
				for _, table := range live.RouteTables {
					for _, association := range table.Associations {
						if aws.ToString(association.SubnetId) != before["Subnet"] {
							continue
						}
						associations++
						if aws.ToString(table.RouteTableId) != before["OriginalTable"] || aws.ToString(association.RouteTableAssociationId) != after["Association"] {
							t.Fatalf("rollback outputs do not name the actual restored owner edge: %+v outputs=%v", association, after)
						}
					}
				}
				if associations != 1 {
					t.Fatalf("expected exactly one actual restored association, got %d", associations)
				}
				if err := repository.View(t.Context(), func(r cfnstore.Reader) error {
					stack, err := r.Stack(aws.ToString(created.StackId))
					if err != nil {
						return err
					}
					op, err := r.Operation(stack.OperationID)
					if err != nil {
						return err
					}
					for _, step := range op.Steps {
						if step.LogicalID != "Association" {
							continue
						}
						if !step.BeforeDeleted || step.Restore.Token == "" || step.Restore.Token == step.Before.Token || step.Restore.Token == step.After.Token || step.Restore.Generation <= step.After.Generation || step.Restore.PhysicalID != after["Association"] {
							t.Fatalf("rollback lacks a durable fresh owner incarnation: %+v", step)
						}
					}
					resources, err := r.Resources(stack.ID)
					if err != nil {
						return err
					}
					foundDeleted, foundCurrent := false, false
					for _, resource := range resources {
						if resource.LogicalID != "Association" {
							continue
						}
						if resource.PhysicalID == before["Association"] {
							foundDeleted = !resource.Current && resource.Status == "DELETE_COMPLETE"
						}
						if resource.PhysicalID == after["Association"] {
							foundCurrent = resource.Current && resource.Status == "UPDATE_COMPLETE"
						}
					}
					if !foundDeleted || !foundCurrent {
						t.Fatalf("deleted history or current restored owner missing: %+v", resources)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				clients = reopen()
				persisted, err := cfn().DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: created.StackId})
				if err != nil || len(persisted.Stacks) != 1 || outputs(persisted.Stacks[0])["Association"] != after["Association"] {
					t.Fatalf("restart lost restored native output: %+v %v", persisted, err)
				}
				if _, err := cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId}); err != nil {
					t.Fatal(err)
				}
				cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusDeleteComplete)
				foreign, err := clients.sqs("test", "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("replacement-foreign-queue")})
				if err != nil {
					t.Fatal("rollback adopted or deleted foreign queue", err)
				}
				if _, err := clients.sqs("test", "test", "").DeleteQueue(t.Context(), &sqs.DeleteQueueInput{QueueUrl: foreign.QueueUrl}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// The EC2 owner rejects this route-table ID only after the controller has
// deleted the old exclusive association. The failed incarnation's subnet claim
// must be released without touching an unrelated live native association.
func TestCloudFormationRejectedExclusiveReplacementRestoresFreshNativeOwner(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 6, 7, 8, 9, 10, 0, time.UTC))
			var repository cfnstore.Repository
			clients, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				repository = config.Storage.CloudFormation
				return startPublicCloud(t, config)
			})
			cfn := func() *cloudformation.Client { return cloudFormationClient(clients, "us-east-1", "test", "test") }
			outputs := func(stack cfntypes.Stack) map[string]string {
				values := map[string]string{}
				for _, output := range stack.Outputs {
					values[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
				}
				return values
			}
			body := cfnAssociationReplacementTemplate(t, "OriginalTable", "rejected-replacement-owned-queue")
			created, err := cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("rejected-exclusive-route-replacement"), TemplateBody: aws.String(body)})
			if err != nil {
				t.Fatal(err)
			}
			before := outputs(cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete))
			native := asgEC2(clients, "us-east-1")
			table, err := native.DescribeRouteTables(t.Context(), &ec2.DescribeRouteTablesInput{RouteTableIds: []string{before["OriginalTable"]}})
			if err != nil || len(table.RouteTables) != 1 {
				t.Fatalf("original native route table: %+v %v", table, err)
			}
			foreignSubnet, err := native.CreateSubnet(t.Context(), &ec2.CreateSubnetInput{VpcId: table.RouteTables[0].VpcId, CidrBlock: aws.String("10.76.2.0/24")})
			if err != nil {
				t.Fatal(err)
			}
			foreignAssociation, err := native.AssociateRouteTable(t.Context(), &ec2.AssociateRouteTableInput{SubnetId: foreignSubnet.Subnet.SubnetId, RouteTableId: aws.String(before["OriginalTable"])})
			if err != nil {
				t.Fatal(err)
			}
			var rejected map[string]any
			if err := json.Unmarshal([]byte(body), &rejected); err != nil {
				t.Fatal(err)
			}
			rejected["Resources"].(map[string]any)["Association"].(map[string]any)["Properties"].(map[string]any)["RouteTableId"] = "rtb-0000000000000ffff"
			rejectedBody, err := json.Marshal(rejected)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(string(rejectedBody))}); err != nil {
				t.Fatal(err)
			}
			after := outputs(cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusUpdateRollbackComplete))
			if after["Association"] == "" || after["Association"] == before["Association"] {
				t.Fatalf("rejected replacement did not really recreate the original association: before=%v after=%v", before, after)
			}
			live, err := native.DescribeRouteTables(t.Context(), &ec2.DescribeRouteTablesInput{RouteTableIds: []string{before["OriginalTable"]}})
			if err != nil {
				t.Fatal(err)
			}
			restored, preserved := false, false
			for _, table := range live.RouteTables {
				for _, association := range table.Associations {
					if aws.ToString(association.SubnetId) == before["Subnet"] {
						restored = aws.ToString(association.RouteTableAssociationId) == after["Association"]
					}
					if aws.ToString(association.SubnetId) == aws.ToString(foreignSubnet.Subnet.SubnetId) {
						preserved = aws.ToString(association.RouteTableAssociationId) == aws.ToString(foreignAssociation.AssociationId)
					}
				}
			}
			if !restored || !preserved {
				t.Fatalf("rollback failed to restore exact native owner or altered foreign association: restored=%v preserved=%v tables=%+v", restored, preserved, live.RouteTables)
			}
			if err := repository.View(t.Context(), func(r cfnstore.Reader) error {
				stack, err := r.Stack(aws.ToString(created.StackId))
				if err != nil {
					return err
				}
				op, err := r.Operation(stack.OperationID)
				if err != nil {
					return err
				}
				found := false
				for _, step := range op.Steps {
					if step.LogicalID != "Association" {
						continue
					}
					found = true
					if !step.BeforeDeleted || step.After.PhysicalID != "" || step.Restore.PhysicalID != after["Association"] || step.Restore.Token == "" || step.Restore.Token == step.Before.Token || step.Restore.Token == step.After.Token {
						t.Fatalf("rejected nonadmission or fresh restored incarnation not retained: %+v", step)
					}
				}
				if !found {
					t.Fatal("association replacement step disappeared")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			persisted, err := cfn().DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: created.StackId})
			if err != nil || len(persisted.Stacks) != 1 || outputs(persisted.Stacks[0])["Association"] != after["Association"] {
				t.Fatalf("restart lost authentic restored identity: %+v %v", persisted, err)
			}
			// A later valid replacement proves the restored token owns the actual
			// native edge, rather than merely reporting a successful rollback.
			if _, err := cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(cfnAssociationReplacementTemplate(t, "ReplacementTable", "rejected-replacement-owned-queue"))}); err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			native = asgEC2(clients, "us-east-1")
			if _, err := native.DisassociateRouteTable(t.Context(), &ec2.DisassociateRouteTableInput{AssociationId: foreignAssociation.AssociationId}); err != nil {
				t.Fatal("foreign association was lost during rollback/replacement", err)
			}
			if _, err := native.DeleteSubnet(t.Context(), &ec2.DeleteSubnetInput{SubnetId: foreignSubnet.Subnet.SubnetId}); err != nil {
				t.Fatal(err)
			}
			if _, err := cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId}); err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusDeleteComplete)
		})
	}
}
