package eks_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	domain "stackd/internal/services/eks"
)

func eksOwnerCommand(t *testing.T, ctx context.Context, s *domain.Service, action string, in any) *awswire.Error {
	t.Helper()
	model, _ := awscatalog.LookupService("eks")
	op, ok := model.Operation(action)
	if !ok {
		t.Fatal(action)
	}
	_, err := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
	return err
}

// These are retained admitted-intent fixtures, not Kubernetes readiness proof.
// Native tagging and claim fencing are deterministic with no runtime installed.
// Typed deletion models the service repository boundary used by completion.
func putEKSOwnerFixture(tx domain.Transaction, key domain.Key, kind, id string, tags map[string]string) (domain.CloudFormationCreation, error) {
	if kind != "Cluster" {
		if _, err := tx.Cluster(key); errors.Is(err, domain.ErrNotFound) {
			if err = tx.PutCluster(domain.Cluster{Key: key, ID: "parent", Status: "CREATING"}); err != nil {
				return domain.CloudFormationCreation{}, err
			}
		} else if err != nil {
			return domain.CloudFormationCreation{}, err
		}
	}
	receipt := domain.CloudFormationCreation{Key: domain.CloudFormationCreationKey{Scope: key.Scope, ResourceType: "AWS::EKS::" + kind, Owner: "deployment-" + kind}, ClusterName: key.Name, NativeName: "child", NativeID: id}
	var err error
	switch kind {
	case "Cluster":
		receipt.NativeName = key.Name
		receipt.PhysicalID = key.Name
		receipt.ARN = key.ARN()
		err = tx.PutCluster(domain.Cluster{Key: key, ID: id, Status: "CREATING", Tags: tags, Created: time.Unix(123, 0)})
	case "Nodegroup":
		row := domain.Nodegroup{Key: domain.NodegroupKey{Cluster: key, Name: "child"}, ID: id, ClusterID: "parent", Status: "CREATING", Tags: tags, Created: time.Unix(123, 0)}
		receipt.PhysicalID = key.Name + "/child"
		receipt.ARN = row.Key.ARN(id)
		err = tx.PutNodegroup(row)
	case "Addon":
		row := domain.Addon{Key: key, Name: "child", ID: id, Status: "CREATING", Tags: tags, Created: time.Unix(123, 0)}
		receipt.PhysicalID = key.Name + "|child"
		receipt.ARN = row.ARN()
		err = tx.PutAddon(row)
	case "FargateProfile":
		row := domain.FargateProfile{Key: key, Name: "child", ID: id, Status: "CREATING", Tags: tags, Created: time.Unix(123, 0)}
		receipt.PhysicalID = key.Name + "|child"
		receipt.ARN = row.ARN()
		err = tx.PutFargateProfile(row)
	case "AccessEntry":
		principal := "arn:aws:iam::" + key.AccountID + ":user/developer"
		receipt.NativeName = principal
		receipt.PhysicalID = principal + "|" + key.Name
		receipt.ARN = "arn:" + key.Partition + ":eks:" + key.Region + ":" + key.AccountID + ":access-entry/" + key.Name + "/user/" + key.AccountID + "/developer/" + id
		err = tx.PutAccessEntry(domain.AccessEntry{Key: key, ID: id, PrincipalARN: principal, PrincipalID: "immutable-user", Tags: tags, Created: time.Unix(123, 0)})
	case "PodIdentityAssociation":
		row := domain.PodIdentityAssociation{Key: key, ID: id, ClusterID: "parent", Namespace: "default", ServiceAccount: "application", Tags: tags, Created: time.Unix(123, 0)}
		receipt.NativeName = id
		receipt.PhysicalID = row.ARN()
		receipt.ARN = row.ARN()
		err = tx.PutPodIdentityAssociation(row)
	default:
		return receipt, fmt.Errorf("unknown kind %s", kind)
	}
	return receipt, err
}
func deleteEKSOwnerFixture(tx domain.Transaction, key domain.Key, receipt domain.CloudFormationCreation) error {
	switch receipt.Key.ResourceType {
	case "AWS::EKS::Cluster":
		return tx.DeleteCluster(key)
	case "AWS::EKS::Nodegroup":
		return tx.DeleteNodegroup(domain.NodegroupKey{Cluster: key, Name: receipt.NativeName})
	case "AWS::EKS::Addon":
		return tx.DeleteAddon(key, receipt.NativeName)
	case "AWS::EKS::FargateProfile":
		return tx.DeleteFargateProfile(key, receipt.NativeName)
	case "AWS::EKS::AccessEntry":
		return tx.DeleteAccessEntry(key, receipt.NativeName)
	case "AWS::EKS::PodIdentityAssociation":
		return tx.DeletePodIdentityAssociation(key, receipt.NativeName)
	}
	return fmt.Errorf("unknown kind")
}
func TestCloudFormationEKSPrivateExactLifecycles(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"Cluster", "Nodegroup", "Addon", "FargateProfile", "AccessEntry", "PodIdentityAssociation"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				stores := openRepositories(t, backend)
				key := clusterKey()
				key.Name = "claim-controls"
				ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PrincipalARN: "arn:aws:iam::" + key.AccountID + ":root", PrincipalID: key.AccountID})
				var receipt domain.CloudFormationCreation
				rollback := errors.New("rollback admission")
				err := stores.repo.Attempt(ctx, func(tx domain.Transaction) error {
					var err error
					receipt, err = putEKSOwnerFixture(tx, key, kind, "first-id", nil)
					if err != nil {
						return err
					}
					if err = tx.PutCloudFormationCreation(receipt); err != nil {
						return err
					}
					return rollback
				})
				if !errors.Is(err, rollback) {
					t.Fatal(err)
				}
				if err = stores.repo.View(ctx, func(r domain.Reader) error {
					_, err := r.CloudFormationCreation(receipt.Key)
					if !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("rolled-back receipt: %v", err)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err = stores.repo.Update(ctx, func(tx domain.Transaction) error {
					var err error
					receipt, err = putEKSOwnerFixture(tx, key, kind, "first-id", map[string]string{"customer": "blue"})
					if err != nil {
						return err
					}
					return tx.PutCloudFormationCreation(receipt)
				}); err != nil {
					t.Fatal(err)
				}
				service := domain.New(domain.Config{Repository: stores.repo})
				t.Cleanup(func() { _ = service.Close() })
				check := func() {
					t.Helper()
					id, err := service.CloudFormationCreation(ctx, receipt.Key.ResourceType, receipt.Key.Owner)
					if err != nil || id != receipt.PhysicalID {
						t.Fatalf("lost reply recovery %q %v", id, err)
					}
				}
				check()
				if err = stores.repo.Update(ctx, func(tx domain.Transaction) error { return tx.PutCloudFormationCreation(receipt) }); err == nil {
					t.Fatal("duplicate incarnation admitted")
				}
				duplicate := receipt
				duplicate.Key.Owner += "-foreign"
				if err = stores.repo.Update(ctx, func(tx domain.Transaction) error { return tx.PutCloudFormationCreation(duplicate) }); err == nil {
					t.Fatal("same native ID claimed twice")
				}
				markers := api.TagMap{"stackd:cloudformation:stack-id": "forged", "stackd:cloudformation:logical-id": "forged", "stackd:cloudformation:incarnation": "forged"}
				if err := eksOwnerCommand(t, ctx, service, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.String(receipt.ARN)), Tags: markers}); err != nil {
					t.Fatal(err)
				}
				wrong := domain.WithCloudFormationMutation(ctx, receipt.Key.ResourceType, receipt.Key.Owner+"-foreign", receipt.PhysicalID)
				if err := eksOwnerCommand(t, wrong, service, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.String(receipt.ARN)), Tags: api.TagMap{}}); err == nil {
					t.Fatal("forged markers authorized a no-op")
				}
				if err := eksOwnerCommand(t, ctx, service, "UntagResource", &api.UntagResourceRequest{ResourceArn: new(api.String(receipt.ARN)), TagKeys: api.TagKeyList{"customer", "stackd:cloudformation:stack-id", "stackd:cloudformation:logical-id", "stackd:cloudformation:incarnation"}}); err != nil {
					t.Fatal(err)
				}
				owned := domain.WithCloudFormationMutation(ctx, receipt.Key.ResourceType, receipt.Key.Owner, receipt.PhysicalID)
				if err := eksOwnerCommand(t, owned, service, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.String(receipt.ARN)), Tags: api.TagMap{}}); err != nil {
					t.Fatalf("marker removal revoked native ownership: %v", err)
				}
				check()
				for _, scope := range []domain.Scope{{Partition: "aws-cn", AccountID: key.AccountID, Region: key.Region}, {Partition: key.Partition, AccountID: "222222222222", Region: key.Region}, {Partition: key.Partition, AccountID: key.AccountID, Region: "us-west-2"}} {
					foreign := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID})
					if _, err := service.CloudFormationCreation(foreign, receipt.Key.ResourceType, receipt.Key.Owner); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("scope leak: %v", err)
					}
				}
				if stores.restart != nil {
					if err = service.Close(); err != nil {
						t.Fatal(err)
					}
					stores.restart()
					service = domain.New(domain.Config{Repository: stores.repo})
				}
				check()
				if err = stores.repo.Update(ctx, func(tx domain.Transaction) error { return deleteEKSOwnerFixture(tx, key, receipt) }); err != nil {
					t.Fatal(err)
				}
				if _, err = service.CloudFormationCreation(ctx, receipt.Key.ResourceType, receipt.Key.Owner); err == nil || errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("deleted receipt allowed readmission: %v", err)
				}
				var replacement domain.CloudFormationCreation
				if err = stores.repo.Update(ctx, func(tx domain.Transaction) error {
					var err error
					replacement, err = putEKSOwnerFixture(tx, key, kind, "replacement-id", map[string]string{"stackd:cloudformation:incarnation": "forged"})
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if err = service.CloudFormationOwned(ctx, receipt.Key.ResourceType, receipt.Key.Owner, replacement.PhysicalID); err == nil {
					t.Fatal("same-name, same-time replacement inherited claim")
				}
				if err := eksOwnerCommand(t, owned, service, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.String(replacement.ARN)), Tags: api.TagMap{}}); err == nil {
					t.Fatal("stale no-op mutated replacement")
				}
				if err = stores.repo.View(ctx, func(r domain.Reader) error {
					rows, err := r.CloudFormationCreations(key.Scope)
					if err != nil {
						return err
					}
					if len(rows) != 1 || rows[0] != receipt {
						t.Fatalf("private receipt transferred: %#v", rows)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
