package identity

import (
	"errors"
	"testing"
	"time"
)

func TestEC2InstanceIdentityCannotChainIntoIAMRole(t *testing.T) {
	store := NewStore("123456789012")
	intrinsic, err := store.IssueEC2InstanceIdentity(t.Context(), EC2InstanceIdentitySpec{InstanceARN: "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0", RoleDelivery: "2.0", Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	// Even an already-authorized role specification must not convert the
	// restricted intrinsic identity into ordinary IAM role permissions.
	_, err = store.IssueRoleSession(t.Context(), intrinsic, RoleSessionSpec{
		Role:        Principal{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:role/worker", ID: "AROAWORKER"},
		SessionName: "escape", Duration: time.Hour, MaxSessionDuration: time.Hour,
	})
	if !errors.Is(err, ErrSessionCredentials) {
		t.Fatalf("intrinsic role chaining = %v; want session restriction", err)
	}
}
