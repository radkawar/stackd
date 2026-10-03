package stackd_test

import (
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/storage"
)

func TestKMSSessionGrantBindingLifecycleMatchesAWS(t *testing.T) {
	codes := kmsNativeCodes(t, "grants")
	backends := storage.NewMemory()
	first, err := stackd.New(stackd.Config{Storage: backends})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(first)
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = first.Close() })
	c := cloudClients{server}
	root, owner := c.iam("test", "test", ""), c.kms("test", "test", "")
	roleInput := &iam.CreateRoleInput{RoleName: aws.String("binding"), Path: aws.String("/application/"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)}
	role, err := root.CreateRole(t.Context(), roleInput)
	if err != nil {
		t.Fatal(err)
	}
	key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	arn := "arn:aws:sts::000000000000:assumed-role/binding/future"
	id := aws.ToString(role.Role.RoleId) + ":future"
	input := &kms.CreateGrantInput{KeyId: key.KeyMetadata.KeyId, Name: aws.String("bound-session"), GranteePrincipal: &arn, RetiringPrincipal: &arn, Operations: []types.GrantOperation{types.GrantOperationDescribeKey}}
	grant, err := owner.CreateGrant(t.Context(), input)
	checkKMSNative(t, codes, "lifecycle_create", err)
	// ARN and raw unique-ID references select the same identity and named grant.
	input.GranteePrincipal, input.RetiringPrincipal = &id, &id
	retry, err := owner.CreateGrant(t.Context(), input)
	checkKMSNative(t, codes, "lifecycle_named_id_retry", err)
	if aws.ToString(retry.GrantId) != aws.ToString(grant.GrantId) {
		t.Fatal("principal spelling duplicated a named grant")
	}
	listed, err := owner.ListGrants(t.Context(), &kms.ListGrantsInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: &id})
	checkKMSNative(t, codes, "lifecycle_filter_id", err)
	if len(listed.Grants) != 1 || aws.ToString(listed.Grants[0].GranteePrincipal) != arn {
		t.Fatal("unique-ID filter did not select and render session ARN", listed)
	}
	retirable, err := owner.ListRetirableGrants(t.Context(), &kms.ListRetirableGrantsInput{RetiringPrincipal: &id})
	checkKMSNative(t, codes, "lifecycle_retirable_id", err)
	if len(retirable.Grants) != 1 || aws.ToString(retirable.Grants[0].RetiringPrincipal) != arn {
		t.Fatal("retiring unique-ID filter did not select and render session ARN", retirable)
	}
	for _, tc := range []struct{ name, principal string }{
		{"missing_role", "arn:aws:sts::000000000000:assumed-role/missing/future"},
		{"session_role_path", "arn:aws:sts::000000000000:assumed-role/application/binding/future"},
		{"unissued_federated_user", "arn:aws:sts::000000000000:federated-user/unissued"},
		{"missing_account_federated_user", "arn:aws:sts::123456789012:federated-user/unissued"},
	} {
		_, err := owner.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: &tc.principal, Operations: []types.GrantOperation{types.GrantOperationDescribeKey}})
		checkKMSNative(t, codes, tc.name, err)
	}
	if _, err := root.DeleteRole(t.Context(), &iam.DeleteRoleInput{RoleName: role.Role.RoleName}); err != nil {
		t.Fatal(err)
	}
	checkOldGrant := func(name string) {
		t.Helper()
		out, err := owner.ListGrants(t.Context(), &kms.ListGrantsInput{KeyId: key.KeyMetadata.KeyId, GrantId: grant.GrantId})
		checkKMSNative(t, codes, name, err)
		if len(out.Grants) != 1 || aws.ToString(out.Grants[0].GranteePrincipal) != id || aws.ToString(out.Grants[0].RetiringPrincipal) != id {
			t.Fatal("deleted session identity was rendered as a current ARN", out)
		}
	}
	checkOldGrant("lifecycle_list_deleted")
	for _, tc := range []struct{ suffix, principal string }{{"arn", arn}, {"id", id}} {
		_, err := owner.ListGrants(t.Context(), &kms.ListGrantsInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: &tc.principal})
		checkKMSNative(t, codes, "lifecycle_filter_deleted_"+tc.suffix, err)
		_, err = owner.ListRetirableGrants(t.Context(), &kms.ListRetirableGrantsInput{RetiringPrincipal: &tc.principal})
		checkKMSNative(t, codes, "lifecycle_retirable_deleted_"+tc.suffix, err)
	}
	_, err = owner.CreateGrant(t.Context(), input)
	checkKMSNative(t, codes, "lifecycle_create_deleted_id", err)
	role, err = root.CreateRole(t.Context(), roleInput)
	if err != nil {
		t.Fatal(err)
	}
	checkOldGrant("lifecycle_list_recreated")
	session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("future")})
	if err != nil {
		t.Fatal(err)
	}
	client := c.sessionKMS(session.Credentials)
	_, err = client.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.KeyId, GrantTokens: []string{aws.ToString(grant.GrantToken)}})
	checkKMSNative(t, codes, "lifecycle_recreated_old_grant", err)
	input.GranteePrincipal, input.RetiringPrincipal = &arn, &arn
	fresh, err := owner.CreateGrant(t.Context(), input)
	checkKMSNative(t, codes, "lifecycle_recreated_named_grant", err)
	if aws.ToString(fresh.GrantId) == aws.ToString(grant.GrantId) {
		t.Fatal("recreated identity recovered old named grant")
	}
	// Reopen all typed stores. Neither the old binding nor new grant tokens
	// may depend on a provider's transient maps or the first server instance.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	server.Close()
	c = clockCloud(t, stackd.Config{Storage: backends})
	owner = c.kms("test", "test", "")
	checkOldGrant("lifecycle_list_recreated")
	client = c.sessionKMS(session.Credentials)
	_, err = client.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.KeyId, GrantTokens: []string{aws.ToString(fresh.GrantToken)}})
	checkKMSNative(t, codes, "lifecycle_recreated_new_grant", err)
	listed, err = owner.ListGrants(t.Context(), &kms.ListGrantsInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: &arn})
	if err != nil || len(listed.Grants) != 1 || aws.ToString(listed.Grants[0].GrantId) != aws.ToString(fresh.GrantId) {
		t.Fatal("recreated principal filter selected old identity", listed, err)
	}
}
