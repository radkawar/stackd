package ec2

import (
	"testing"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// This exercises the native control-plane state transition and private admission
// transaction only. It neither launches a guest nor installs an executor that
// pretends one ran. Real launch prerequisite rejection is tested separately.
func TestCloudFormationInstanceTerminalClaimTransition(t *testing.T) {
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	repo := NewMemoryRepository(nil)
	service := New(Config{Repository: repo})
	t.Cleanup(func() { _ = service.Close() })
	const resourceType = "AWS::EC2::Instance"
	const owner = "stack/Instance/incarnation"
	var id string
	err := repo.Update(WithCloudFormationCreation(root, resourceType, owner), func(tx Transaction) error {
		owned, admission, err := beginCloudFormationOwner(tx.Context(), tx)
		if err != nil {
			return err
		}
		id, err = owned.NextID(scopeFor(tx.Context()), "i")
		if err != nil {
			return err
		}
		record := InstanceRecord{Key: key(tx.Context(), id), Data: api.Instance{InstanceId: new(api.String(id))}}
		if err := service.changeInstanceState(tx.Context(), owned, &record, "stopped"); err != nil {
			return err
		}
		return admission.finish(tx.Context())
	})
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := service.CloudFormationCreation(root, resourceType, owner); err != nil || recovered != id {
		t.Fatalf("stopped receipt %q %v", recovered, err)
	}
	for _, state := range []string{"shutting-down", "terminated"} {
		if err := repo.Update(root, func(tx Transaction) error {
			record, err := tx.Instance(key(tx.Context(), id))
			if err != nil {
				return err
			}
			return service.changeInstanceState(tx.Context(), tx, &record, state)
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := service.CloudFormationCreation(root, resourceType, owner); err == nil {
			t.Fatalf("%s tombstone recovered as a creation", state)
		}
		if err := service.CloudFormationOwned(root, resourceType, owner, id); err != nil {
			t.Fatalf("%s deletion observation lost exact claim: %v", state, err)
		}
		if err := service.CloudFormationOwned(root, resourceType, owner+"-foreign", id); err == nil {
			t.Fatalf("%s tombstone accepted another incarnation", state)
		}
		err := repo.Update(WithCloudFormationMutation(root, resourceType, owner, id), func(tx Transaction) error {
			owned, _, err := beginCloudFormationOwner(tx.Context(), tx)
			if err != nil {
				return err
			}
			_, err = service.startInstances(tx.Context(), owned, &api.StartInstancesRequest{InstanceIds: api.InstanceIdStringList{api.InstanceId(id)}})
			return err
		})
		if err == nil {
			t.Fatalf("%s tombstone allowed native start", state)
		}
	}
	var replacement string
	if err := repo.Update(root, func(tx Transaction) error {
		var err error
		replacement, err = tx.NextID(scopeFor(tx.Context()), "i")
		if err != nil {
			return err
		}
		return tx.PutInstance(InstanceRecord{Key: key(tx.Context(), replacement), Data: api.Instance{InstanceId: new(api.String(replacement)), State: instanceStateValue("stopped")}})
	}); err != nil {
		t.Fatal(err)
	}
	if replacement == id {
		t.Fatal("native replacement reused immutable instance ID")
	}
	if err := service.CloudFormationOwned(root, resourceType, owner, replacement); err == nil {
		t.Fatal("new native row inherited tombstone claim")
	}
}
