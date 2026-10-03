package stackd_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
	"stackd/clock"
)

func TestKMSMultiRegionDeletionOrderAndServiceRole(t *testing.T) {
	codes := kmsNativeCodes(t, "multi_region")
	source := clock.NewManual(time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source})
	east, west := c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
	root := c.iam("test", "test", "")
	created, err := east.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	id := created.KeyMetadata.KeyId
	roleName := aws.String("AWSServiceRoleForKeyManagementServiceMultiRegionKeys")
	role, err := root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: roleName})
	checkKMSNative(t, codes, "service_role_after", err)
	if aws.ToString(role.Role.Path) != "/aws-service-role/mrk.kms.amazonaws.com/" || aws.ToString(role.Role.Description) != "Enables access to AWS services and resources required for AWS KMS Multi-Region Keys" {
		t.Fatal("wrong KMS service role", role)
	}
	policies, err := root.ListAttachedRolePolicies(t.Context(), &iam.ListAttachedRolePoliciesInput{RoleName: roleName})
	if err != nil || len(policies.AttachedPolicies) != 1 || aws.ToString(policies.AttachedPolicies[0].PolicyArn) != "arn:aws:iam::aws:policy/aws-service-role/AWSKeyManagementServiceMultiRegionKeysServiceRolePolicy" {
		t.Fatal("incorrect service role permission", policies, err)
	}
	_, err = root.DetachRolePolicy(t.Context(), &iam.DetachRolePolicyInput{RoleName: roleName, PolicyArn: policies.AttachedPolicies[0].PolicyArn})
	assertAPIError(t, err, "UnmodifiableEntity")
	if _, err := east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2")}); err != nil {
		t.Fatal(err)
	}
	if _, err := west.CreateAlias(t.Context(), &kms.CreateAliasInput{AliasName: aws.String("alias/replica"), TargetKeyId: id}); err != nil {
		t.Fatal("Creating permits aliases", err)
	}
	advanceClock(t, source, 5*time.Second)
	if _, err := east.EnableKeyRotation(t.Context(), &kms.EnableKeyRotationInput{KeyId: id}); err != nil {
		t.Fatal(err)
	}
	waiting, err := east.ScheduleKeyDeletion(t.Context(), &kms.ScheduleKeyDeletionInput{KeyId: id, PendingWindowInDays: aws.Int32(7)})
	checkKMSNative(t, codes, "delete_primary_with_replica", err)
	if waiting.KeyState != types.KeyStatePendingReplicaDeletion || waiting.DeletionDate != nil {
		t.Fatal("primary deletion must wait", waiting)
	}
	out, err := east.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
	if err != nil || aws.ToInt32(out.KeyMetadata.PendingDeletionWindowInDays) != 7 || out.KeyMetadata.DeletionDate != nil {
		t.Fatal("lost waiting window", out, err)
	}
	if _, err := west.Encrypt(t.Context(), &kms.EncryptInput{KeyId: id, Plaintext: []byte("replica still usable")}); err != nil {
		t.Fatal(err)
	}
	_, err = east.CancelKeyDeletion(t.Context(), &kms.CancelKeyDeletionInput{KeyId: id})
	checkKMSNative(t, codes, "primary_cancel_replica_wait", err)
	out, err = east.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
	if err != nil || out.KeyMetadata.KeyState != types.KeyStateDisabled || out.KeyMetadata.PendingDeletionWindowInDays != nil {
		t.Fatal("cancel did not disable and clear window", out, err)
	}
	if _, err := east.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: id}); err != nil {
		t.Fatal(err)
	}
	if _, err := east.ScheduleKeyDeletion(t.Context(), &kms.ScheduleKeyDeletionInput{KeyId: id, PendingWindowInDays: aws.Int32(7)}); err != nil {
		t.Fatal(err)
	}
	replicaDeadline := source.Now().Add(7 * 24 * time.Hour)
	if _, err := west.ScheduleKeyDeletion(t.Context(), &kms.ScheduleKeyDeletionInput{KeyId: id, PendingWindowInDays: aws.Int32(7)}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		client *kms.Client
		region string
	}{{east, "us-west-2"}, {west, "us-east-1"}} {
		status, err := tc.client.GetKeyRotationStatus(t.Context(), &kms.GetKeyRotationStatusInput{KeyId: id})
		checkKMSNative(t, codes, "deleting_rotation_"+tc.region, err)
		// Native PendingReplicaDeletion retains the enabled configuration;
		// PendingDeletion reports it disabled. Neither state performs rotations.
		if status.KeyRotationEnabled != (tc.client == east) {
			t.Fatal("rotation status differs from native deletion state", status)
		}
		policy, err := tc.client.GetKeyPolicy(t.Context(), &kms.GetKeyPolicyInput{KeyId: id, PolicyName: aws.String("default")})
		if err != nil {
			t.Fatal(err)
		}
		_, err = tc.client.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: id, Policy: policy.Policy})
		checkKMSNative(t, codes, "put_deleting_policy_"+tc.region, err)
		_, err = tc.client.TagResource(t.Context(), &kms.TagResourceInput{KeyId: id, Tags: []types.Tag{{TagKey: aws.String("cleanup-probe"), TagValue: aws.String("native")}}})
		checkKMSNative(t, codes, "tag_deleting_"+tc.region, err)
		_, err = tc.client.UntagResource(t.Context(), &kms.UntagResourceInput{KeyId: id, TagKeys: []string{"cleanup-probe"}})
		checkKMSNative(t, codes, "untag_deleting_"+tc.region, err)
	}
	deletion, err := root.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: roleName})
	if err != nil {
		t.Fatal(err)
	}
	job := waitOrganizationRoleDeletion(t, root, deletion.DeletionTaskId)
	if job.Status != iamtypes.DeletionTaskStatusTypeFailed || aws.ToString(job.Reason.Reason) != "Account owns one or more multi-Region keys" || len(job.Reason.RoleUsageList) != 2 {
		t.Fatal("role deletion ignored regional keys", job)
	}
	// Observing two days late must not start a new seven-day primary window.
	advanceClock(t, source, 9*24*time.Hour)
	out, err = east.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
	if err != nil || out.KeyMetadata.KeyState != types.KeyStatePendingDeletion || !out.KeyMetadata.DeletionDate.Equal(replicaDeadline.Add(7*24*time.Hour)) || len(out.KeyMetadata.MultiRegionConfiguration.ReplicaKeys) != 0 {
		t.Fatal("primary deadline depends on observation time", out, err)
	}
	_, err = west.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
	assertAPIError(t, err, "NotFoundException")
	_, err = west.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: aws.String("alias/replica")})
	assertAPIError(t, err, "NotFoundException")
	advanceClock(t, source, 5*24*time.Hour)
	// The deletion checker itself advances expired regional keys, even without
	// a KMS request to reap the primary first.
	deletion, err = root.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: roleName})
	if err != nil {
		t.Fatal(err)
	}
	if job := waitOrganizationRoleDeletion(t, root, deletion.DeletionTaskId); job.Status != iamtypes.DeletionTaskStatusTypeSucceeded {
		t.Fatal("expired keys retained service-role dependency", job)
	}
	_, err = east.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: id})
	assertAPIError(t, err, "NotFoundException")
}
