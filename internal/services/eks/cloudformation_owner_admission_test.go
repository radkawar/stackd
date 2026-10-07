package eks

import (
	"context"
	"errors"
	"testing"

	"stackd/internal/awsctx"
)

// Exercise the native admission transaction itself without a Kubernetes runtime.
// These queued-intent rows do not assert guest or Kubernetes readiness.
func TestCloudFormationEKSAdmissionTracksOnlyNewNativeRows(t *testing.T) {
	for _, kind := range []string{"Cluster", "Nodegroup", "Addon", "FargateProfile", "AccessEntry", "PodIdentityAssociation"} {
		t.Run(kind, func(t *testing.T) {
			repo := NewMemoryRepository(nil)
			root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
			key := Key{Scope: scopeFor(root), Name: "admission"}
			intent := cloudFormationIntent{ResourceType: "AWS::EKS::" + kind, Owner: "exact-deployment", Create: true}
			put := func(tx Transaction, id string) error {
				switch kind {
				case "Cluster":
					return tx.PutCluster(Cluster{Key: key, ID: id, Status: "CREATING"})
				case "Nodegroup":
					return tx.PutNodegroup(Nodegroup{Key: NodegroupKey{Cluster: key, Name: "child"}, ID: id, Status: "CREATING"})
				case "Addon":
					return tx.PutAddon(Addon{Key: key, Name: "child", ID: id, Status: "CREATING"})
				case "FargateProfile":
					return tx.PutFargateProfile(FargateProfile{Key: key, Name: "child", ID: id, Status: "CREATING"})
				case "AccessEntry":
					return tx.PutAccessEntry(AccessEntry{Key: key, PrincipalARN: "arn:aws:iam::111111111111:user/developer", ID: id})
				case "PodIdentityAssociation":
					return tx.PutPodIdentityAssociation(PodIdentityAssociation{Key: key, ID: id, Namespace: "default", ServiceAccount: "application"})
				}
				t.Fatal(kind)
				return nil
			}
			receiptKey := CloudFormationCreationKey{Scope: key.Scope, ResourceType: intent.ResourceType, Owner: intent.Owner}
			rollback := errors.New("reject after native row")
			if err := repo.Attempt(root, func(tx Transaction) error {
				admission := &cloudFormationTransaction{Transaction: tx, intent: intent}
				if err := put(admission, "immutable"); err != nil {
					return err
				}
				if err := admission.finish(); err != nil {
					return err
				}
				return rollback
			}); !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			if err := repo.View(root, func(r Reader) error {
				_, err := r.CloudFormationCreation(receiptKey)
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("rolled-back claim survived: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.Update(root, func(tx Transaction) error {
				admission := &cloudFormationTransaction{Transaction: tx, intent: intent}
				if err := put(admission, "immutable"); err != nil {
					return err
				}
				return admission.finish()
			}); err != nil {
				t.Fatal(err)
			}
			var receipt CloudFormationCreation
			if err := repo.View(root, func(r Reader) error {
				var err error
				receipt, err = r.CloudFormationCreation(receiptKey)
				if err != nil {
					return err
				}
				if receipt.NativeID != "immutable" {
					t.Fatal(receipt)
				}
				_, _, err = cloudFormationLive(r, receipt)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// A native token replay writes no genuinely new row and cannot import one.
			foreign := intent
			foreign.Owner = "foreign-deployment"
			if err := repo.Attempt(root, func(tx Transaction) error {
				admission := &cloudFormationTransaction{Transaction: tx, intent: foreign}
				if err := put(admission, "immutable"); err != nil {
					return err
				}
				return admission.finish()
			}); err == nil {
				t.Fatal("existing native row adopted on replay")
			}
			service := New(Config{Repository: repo})
			t.Cleanup(func() { _ = service.Close() })
			// Receipt admission is rejected at the authorization hook before a create
			// can reach dependency owners; no native replay can adopt the admitted row.
			if err := repo.Attempt(root, func(tx Transaction) error {
				ctx := WithCloudFormationCreation(tx.Context(), intent.ResourceType, intent.Owner)
				ctx = context.WithValue(ctx, cloudFormationTransactionKey{}, tx)
				return service.authorizeResource(ctx, key.ARN(), nil, "Create"+kind, nil)
			}); err == nil {
				t.Fatal("one incarnation readmitted creation")
			}
		})
	}
}
