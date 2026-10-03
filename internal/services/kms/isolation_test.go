package kms

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd/internal/awsctx"
)

func TestSDKAliasesTagsAndPaginationIsolation(t *testing.T) {
	s := New()
	sc := rootMetadata("111122223333", "us-east-1", "aws")
	c := sdkClient(t, s, sc)
	ctx := context.Background()
	k1, k2 := createSDKKey(t, c), createSDKKey(t, c)
	for _, name := range []string{"alias/beta", "alias/alpha"} {
		if _, err := c.CreateAlias(ctx, &sdkkms.CreateAliasInput{AliasName: aws.String(name), TargetKeyId: k1.KeyId}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := c.CreateAlias(ctx, &sdkkms.CreateAliasInput{AliasName: aws.String("alias/alpha"), TargetKeyId: k2.KeyId})
	requireCode(t, err, "AlreadyExistsException")
	_, err = c.CreateAlias(ctx, &sdkkms.CreateAliasInput{AliasName: aws.String("alias/aws/reserved"), TargetKeyId: k2.KeyId})
	requireCode(t, err, "NotAuthorizedException")
	aliases, err := c.ListAliases(ctx, &sdkkms.ListAliasesInput{Limit: aws.Int32(1), KeyId: k1.KeyId})
	if err != nil || len(aliases.Aliases) != 1 || aws.ToString(aliases.Aliases[0].AliasName) != "alias/alpha" || !aliases.Truncated || aliases.NextMarker == nil || aliases.Aliases[0].CreationDate == nil {
		t.Fatalf("first aliases: %+v, %v", aliases, err)
	}
	next, err := c.ListAliases(ctx, &sdkkms.ListAliasesInput{Limit: aws.Int32(1), KeyId: k1.KeyId, Marker: aliases.NextMarker})
	if err != nil || len(next.Aliases) != 1 || aws.ToString(next.Aliases[0].AliasName) != "alias/beta" || next.Truncated {
		t.Fatalf("next aliases: %+v, %v", next, err)
	}
	_, err = c.ListAliases(ctx, &sdkkms.ListAliasesInput{KeyId: k2.KeyId, Marker: aliases.NextMarker})
	requireCode(t, err, "InvalidMarkerException")
	if _, err := c.UpdateAlias(ctx, &sdkkms.UpdateAliasInput{AliasName: aws.String("alias/alpha"), TargetKeyId: k2.Arn}); err != nil {
		t.Fatal(err)
	}
	described, err := c.DescribeKey(ctx, &sdkkms.DescribeKeyInput{KeyId: aws.String("arn:aws:kms:us-east-1:111122223333:alias/alpha")})
	if err != nil || aws.ToString(described.KeyMetadata.KeyId) != aws.ToString(k2.KeyId) {
		t.Fatalf("retargeted alias: %+v, %v", described, err)
	}
	if _, err := c.DeleteAlias(ctx, &sdkkms.DeleteAliasInput{AliasName: aws.String("alias/alpha")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TagResource(ctx, &sdkkms.TagResourceInput{KeyId: k1.KeyId, Tags: []types.Tag{{TagKey: aws.String("team"), TagValue: aws.String("first")}, {TagKey: aws.String("a"), TagValue: aws.String("")}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TagResource(ctx, &sdkkms.TagResourceInput{KeyId: k1.KeyId, Tags: []types.Tag{{TagKey: aws.String("team"), TagValue: aws.String("second")}}}); err != nil {
		t.Fatal(err)
	}
	tags, err := c.ListResourceTags(ctx, &sdkkms.ListResourceTagsInput{KeyId: k1.KeyId, Limit: aws.Int32(1)})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].TagKey) != "a" || !tags.Truncated {
		t.Fatalf("tags: %+v, %v", tags, err)
	}
	_, err = c.ListKeys(ctx, &sdkkms.ListKeysInput{Marker: tags.NextMarker})
	requireCode(t, err, "InvalidMarkerException")
	if _, err := c.UntagResource(ctx, &sdkkms.UntagResourceInput{KeyId: k1.KeyId, TagKeys: []string{"a", "missing"}}); err != nil {
		t.Fatal(err)
	}
	tags, err = c.ListResourceTags(ctx, &sdkkms.ListResourceTagsInput{KeyId: k1.KeyId})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].TagValue) != "second" {
		t.Fatalf("updated tags: %+v, %v", tags, err)
	}
	_, err = c.TagResource(ctx, &sdkkms.TagResourceInput{KeyId: k1.KeyId, Tags: []types.Tag{{TagKey: aws.String("valid"), TagValue: aws.String("new")}, {TagKey: aws.String("aws:reserved"), TagValue: aws.String("bad")}}})
	requireCode(t, err, "TagException")
	tags, err = c.ListResourceTags(ctx, &sdkkms.ListResourceTagsInput{KeyId: k1.KeyId})
	if err != nil || len(tags.Tags) != 1 {
		t.Fatalf("non-atomic tag mutation: %+v, %v", tags, err)
	}
	keys, err := c.ListKeys(ctx, &sdkkms.ListKeysInput{Limit: aws.Int32(1)})
	if err != nil || len(keys.Keys) != 1 || !keys.Truncated {
		t.Fatalf("keys: %+v, %v", keys, err)
	}
	for _, other := range []awsctx.Metadata{rootMetadata("444455556666", sc.Region, sc.Partition), rootMetadata(sc.AccountID, "eu-west-1", sc.Partition), rootMetadata(sc.AccountID, sc.Region, "aws-us-gov")} {
		foreign := sdkClient(t, s, other)
		_, err := foreign.DescribeKey(ctx, &sdkkms.DescribeKeyInput{KeyId: k1.Arn})
		if other.AccountID != sc.AccountID {
			requireCode(t, err, "AccessDeniedException")
		} else {
			requireCode(t, err, "NotFoundException")
		}
		_, err = foreign.DescribeKey(ctx, &sdkkms.DescribeKeyInput{KeyId: k1.KeyId})
		requireCode(t, err, "NotFoundException")
		_, err = foreign.ListKeys(ctx, &sdkkms.ListKeysInput{Marker: keys.NextMarker})
		requireCode(t, err, "InvalidMarkerException")
		listed, err := foreign.ListKeys(ctx, &sdkkms.ListKeysInput{})
		if err != nil || len(listed.Keys) != 0 {
			t.Fatalf("foreign listing: %+v, %v", listed, err)
		}
	}
}

func TestSDKKeyPolicyAndServiceEncryption(t *testing.T) {
	s := New()
	sc := rootMetadata("111122223333", "us-east-1", "aws")
	c := sdkClient(t, s, sc)
	ctx := context.Background()
	k := createSDKKey(t, c)
	got, err := c.GetKeyPolicy(ctx, &sdkkms.GetKeyPolicyInput{KeyId: k.KeyId, PolicyName: aws.String("default")})
	if err != nil || !strings.Contains(aws.ToString(got.Policy), sc.PrincipalARN) {
		t.Fatalf("default policy: %+v, %v", got, err)
	}
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":"kms:Encrypt","Resource":"*","Condition":{"StringNotEquals":{"kms:EncryptionContext:purpose":"allowed"}}}]}`, sc.PrincipalARN)
	if _, err := c.PutKeyPolicy(ctx, &sdkkms.PutKeyPolicyInput{KeyId: k.KeyId, Policy: aws.String(policy)}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("hello")})
	requireCode(t, err, "AccessDeniedException")
	if _, err := c.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("hello"), EncryptionContext: map[string]string{"purpose": "allowed"}}); err != nil {
		t.Fatal(err)
	}
	lockout := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"kms:*","Resource":"*"}]}`
	_, err = c.PutKeyPolicy(ctx, &sdkkms.PutKeyPolicyInput{KeyId: k.KeyId, Policy: aws.String(lockout)})
	requireCode(t, err, "MalformedPolicyDocumentException")
	still, err := c.GetKeyPolicy(ctx, &sdkkms.GetKeyPolicyInput{KeyId: k.KeyId})
	if err != nil || aws.ToString(still.Policy) != policy {
		t.Fatalf("rejected policy mutated state: %+v, %v", still, err)
	}
	root := awsctx.WithMetadata(ctx, sc)
	arn, keyErr := s.EnsureServiceKey(root, "sqs")
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	arnAgain, keyErr := s.EnsureServiceKey(root, "sqs")
	if keyErr != nil || arnAgain != arn {
		t.Fatalf("managed key is not stable: %s, %v", arnAgain, keyErr)
	}
	managed, err := c.DescribeKey(ctx, &sdkkms.DescribeKeyInput{KeyId: aws.String("alias/aws/sqs")})
	if err != nil || managed.KeyMetadata.KeyManager != types.KeyManagerTypeAws {
		t.Fatalf("managed metadata: %+v, %v", managed, err)
	}
	_, err = c.DisableKey(ctx, &sdkkms.DisableKeyInput{KeyId: aws.String(arn)})
	requireCode(t, err, "AccessDeniedException")
	_, _, keyErr = s.Encrypt(root, arn, []byte("hello"), nil)
	if keyErr == nil || keyErr.Code != "AccessDeniedException" {
		t.Fatalf("managed key permitted direct encryption: %v", keyErr)
	}
	viaSQS := WithViaService(root, "sqs")
	context := map[string]string{"aws:sqs:queuearn": "arn:aws:sqs:us-east-1:111122223333:queue"}
	plain, ciphertext, keyARN, keyErr := s.GenerateDataKey(viaSQS, arn, context)
	if keyErr != nil || len(plain) != 32 || keyARN != arn {
		t.Fatalf("service data key: %d, %s, %v", len(plain), keyARN, keyErr)
	}
	decoded, _, keyErr := s.Decrypt(viaSQS, ciphertext, context)
	if keyErr != nil || !bytes.Equal(decoded, plain) {
		t.Fatalf("service decrypt: %v", keyErr)
	}
	_, _, keyErr = s.Decrypt(WithViaService(root, "ssm"), ciphertext, context)
	if keyErr == nil || keyErr.Code != "AccessDeniedException" {
		t.Fatalf("wrong service permitted: %v", keyErr)
	}
}
