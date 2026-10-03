package stackd_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
	"stackd/clock"
)

func TestKMSMultiRegionRegionalPermissions(t *testing.T) {
	codes := kmsNativeCodes(t, "multi_region")
	source := clock.NewManual(time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source})
	root := c.iam("test", "test", "")
	east, west := c.kms("test", "test", ""), c.kmsRegion("us-west-2", "test", "test", "")
	_, access, secret := c.user(t, "test", "mrk-operator")
	operator := c.kms(access, secret, "")
	createPolicy := `{"Statement":[{"Effect":"Allow","Action":"kms:CreateKey","Resource":"*","Condition":{"Bool":{"kms:MultiRegion":"true"}}}]}`
	putUserPolicy(t, root, "mrk-operator", createPolicy)
	_, err := operator.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
	assertAPIError(t, err, "AccessDeniedException")
	roles, err := root.ListRoles(t.Context(), &iam.ListRolesInput{PathPrefix: aws.String("/aws-service-role/mrk.kms.amazonaws.com/")})
	if err != nil || len(roles.Roles) != 0 {
		t.Fatal("denied dependent creation left a role", roles, err)
	}
	list, err := east.ListKeys(t.Context(), &kms.ListKeysInput{})
	if err != nil || len(list.Keys) != 0 {
		t.Fatal("denied dependent creation left a key", list, err)
	}
	created, err := east.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	id := created.KeyMetadata.KeyId
	primaryARN := aws.ToString(created.KeyMetadata.Arn)
	replicaARN := "arn:aws:kms:us-west-2:000000000000:key/" + aws.ToString(id)
	// The native account has the role already. Even an explicit IAM creation
	// denial does not prevent KMS creation in that case.
	putUserPolicy(t, root, "mrk-operator", `{"Statement":[{"Effect":"Allow","Action":"kms:CreateKey","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateServiceLinkedRole","Resource":"*"}]}`)
	_, err = operator.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
	checkKMSNative(t, kmsNativeCodes(t, "multi_region_permissions"), "existing_role_iam_creation_denied", err)
	for _, region := range []string{"us-east-1", "cn-north-1", "us-invalid-1"} {
		_, err = east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: &region})
		checkKMSNative(t, codes, "replicate_region_"+region, err)
	}
	_, err = east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("ap-east-1")})
	assertAPIError(t, err, "ValidationException")
	enableAccountRegion(t, c, source, "test", "ap-east-1")
	if _, err := east.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("ap-east-1")}); err != nil {
		t.Fatal("enabled opt-in Region rejected", err)
	}
	replicatePolicy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"kms:ReplicateKey","Resource":%q,"Condition":{"StringEquals":{"kms:ReplicaRegion":"us-west-2","kms:MultiRegionKeyType":"PRIMARY"}}}]}`, primaryARN)
	putUserPolicy(t, root, "mrk-operator", replicatePolicy)
	input := &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-west-2"), Tags: []types.Tag{{TagKey: aws.String("region"), TagValue: aws.String("west")}}}
	_, err = operator.ReplicateKey(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	creation := `{"Effect":"Allow","Action":"kms:CreateKey","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-west-2"},"Bool":{"kms:MultiRegion":"true"}}}`
	grantCreation := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"kms:ReplicateKey","Resource":%q},%s]}`, primaryARN, creation)
	putUserPolicy(t, root, "mrk-operator", grantCreation)
	_, err = operator.ReplicateKey(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException") // TagResource is separate.
	list, err = west.ListKeys(t.Context(), &kms.ListKeysInput{})
	if err != nil || len(list.Keys) != 0 {
		t.Fatal("denied replication left regional state", list, err)
	}
	putUserPolicy(t, root, "mrk-operator", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"kms:ReplicateKey","Resource":%q},%s,{"Effect":"Allow","Action":"kms:TagResource","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-west-2","aws:RequestTag/region":"west"}}}]}`, primaryARN, creation))
	replica, err := operator.ReplicateKey(t.Context(), input)
	if err != nil || len(replica.ReplicaTags) != 1 {
		t.Fatal("regional replication permissions", replica, err)
	}
	advanceClock(t, source, 5*time.Second)
	_, err = east.ReplicateKey(t.Context(), input)
	checkKMSNative(t, codes, "replicate_existing", err)
	_, err = west.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-east-2")})
	checkKMSNative(t, codes, "replicate_replica", err)
	for _, tc := range []struct {
		client       *kms.Client
		name, region string
	}{{east, "update_primary_same", "us-east-1"}, {east, "update_primary_missing", "us-east-2"}, {west, "update_from_replica", "us-west-2"}} {
		_, err = tc.client.UpdatePrimaryRegion(t.Context(), &kms.UpdatePrimaryRegionInput{KeyId: id, PrimaryRegion: &tc.region})
		checkKMSNative(t, codes, tc.name, err)
	}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"replica_enable-key-rotation", func() error {
			_, err := west.EnableKeyRotation(t.Context(), &kms.EnableKeyRotationInput{KeyId: id})
			return err
		}},
		{"replica_disable-key-rotation", func() error {
			_, err := west.DisableKeyRotation(t.Context(), &kms.DisableKeyRotationInput{KeyId: id})
			return err
		}},
		{"replica_rotate-key-on-demand", func() error {
			_, err := west.RotateKeyOnDemand(t.Context(), &kms.RotateKeyOnDemandInput{KeyId: id})
			return err
		}},
	} {
		checkKMSNative(t, codes, tc.name, tc.call())
	}
	putUserPolicy(t, root, "mrk-operator", allow(`"kms:UpdatePrimaryRegion"`, primaryARN))
	promote := &kms.UpdatePrimaryRegionInput{KeyId: id, PrimaryRegion: aws.String("us-west-2")}
	_, err = operator.UpdatePrimaryRegion(t.Context(), promote)
	assertAPIError(t, err, "AccessDeniedException")
	putUserPolicy(t, root, "mrk-operator", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"kms:UpdatePrimaryRegion","Resource":[%q,%q],"Condition":{"StringEquals":{"kms:PrimaryRegion":"us-west-2"}}}]}`, primaryARN, replicaARN))
	// A destination key policy denial still wins over identity permissions.
	deny := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":"kms:UpdatePrimaryRegion","Resource":"*"}]}`
	if _, err := west.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: id, Policy: &deny}); err != nil {
		t.Fatal(err)
	}
	_, err = operator.UpdatePrimaryRegion(t.Context(), promote)
	assertAPIError(t, err, "AccessDeniedException")
	original := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"}]}`
	if _, err := west.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: id, Policy: &original}); err != nil {
		t.Fatal(err)
	}
	if _, err := east.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: id}); err != nil {
		t.Fatal(err)
	}
	_, err = east.UpdatePrimaryRegion(t.Context(), promote)
	checkKMSNative(t, codes, "promote_disabled_primary", err)
	if _, err := east.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: id}); err != nil {
		t.Fatal(err)
	}
	if _, err := west.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: id}); err != nil {
		t.Fatal(err)
	}
	_, err = east.UpdatePrimaryRegion(t.Context(), promote)
	checkKMSNative(t, codes, "promote_disabled_replica", err)
	if _, err := west.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: id}); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.UpdatePrimaryRegion(t.Context(), promote); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 5*time.Second)
	// Deleting a replica prevents recreating or promoting that Region.
	if _, err := east.ScheduleKeyDeletion(t.Context(), &kms.ScheduleKeyDeletionInput{KeyId: id, PendingWindowInDays: aws.Int32(7)}); err != nil {
		t.Fatal(err)
	}
	_, err = west.ReplicateKey(t.Context(), &kms.ReplicateKeyInput{KeyId: id, ReplicaRegion: aws.String("us-east-1")})
	checkKMSNative(t, codes, "replicate_deleting_replica", err)
	_, err = west.UpdatePrimaryRegion(t.Context(), &kms.UpdatePrimaryRegionInput{KeyId: id, PrimaryRegion: aws.String("us-east-1")})
	checkKMSNative(t, codes, "promote_deleting_replica", err)
}
