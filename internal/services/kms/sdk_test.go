package kms

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awsctx"
)

func rootMetadata(account, region, partition string) awsctx.Metadata {
	return awsctx.Metadata{AccountID: account, Region: region, Partition: partition, PrincipalARN: fmt.Sprintf("arn:%s:iam::%s:root", partition, account), PrincipalID: account, RequestID: "kms-sdk-test"}
}

func sdkClient(t *testing.T, s *Service, metadata awsctx.Metadata) *sdkkms.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authentication is covered by gateway integration tests. This middleware
		// gives each SDK client a fixed, verified principal and regional scope.
		s.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), metadata)))
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = s.Close() })
	return sdkkms.New(sdkkms.Options{Region: metadata.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
}

func createSDKKey(t *testing.T, c *sdkkms.Client) *types.KeyMetadata {
	t.Helper()
	out, err := c.CreateKey(context.Background(), &sdkkms.CreateKeyInput{Description: aws.String("test key")})
	if err != nil {
		t.Fatal(err)
	}
	return out.KeyMetadata
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var api smithy.APIError
	if !errors.As(err, &api) || api.ErrorCode() != code {
		t.Fatalf("error = %v; want %s", err, code)
	}
}

func TestSDKKeyLifecycle(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	source := clock.NewManual(now)
	s := NewWithConfig(Config{Clock: source})
	c := sdkClient(t, s, rootMetadata("111122223333", "us-east-1", "aws"))
	ctx := context.Background()
	k := createSDKKey(t, c)
	if k.KeySpec != types.KeySpecSymmetricDefault || k.KeyUsage != types.KeyUsageTypeEncryptDecrypt || k.KeyState != types.KeyStateEnabled || k.KeyManager != types.KeyManagerTypeCustomer || k.Origin != types.OriginTypeAwsKms || !k.Enabled || !k.CreationDate.Equal(now) || len(k.EncryptionAlgorithms) != 1 || aws.ToBool(k.MultiRegion) {
		t.Fatalf("incorrect metadata: %+v", k)
	}
	if _, err := c.UpdateKeyDescription(ctx, &sdkkms.UpdateKeyDescriptionInput{KeyId: k.KeyId, Description: aws.String("updated")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DisableKey(ctx, &sdkkms.DisableKeyInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	_, err := c.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("secret")})
	var disabled *types.DisabledException
	if !errors.As(err, &disabled) {
		t.Fatalf("disabled key error: %v", err)
	}
	if _, err := c.EnableKey(ctx, &sdkkms.EnableKeyInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	scheduled, err := c.ScheduleKeyDeletion(ctx, &sdkkms.ScheduleKeyDeletionInput{KeyId: k.KeyId, PendingWindowInDays: aws.Int32(7)})
	if err != nil {
		t.Fatal(err)
	}
	if scheduled.KeyState != types.KeyStatePendingDeletion || !scheduled.DeletionDate.Equal(now.Add(7*24*time.Hour)) || aws.ToString(scheduled.KeyId) != aws.ToString(k.Arn) {
		t.Fatalf("incorrect deletion metadata: %+v", scheduled)
	}
	_, err = c.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k.KeyId, Plaintext: []byte("secret")})
	requireCode(t, err, "KMSInvalidStateException")
	_, err = c.EnableKey(ctx, &sdkkms.EnableKeyInput{KeyId: k.KeyId})
	requireCode(t, err, "KMSInvalidStateException")
	if _, err := c.CancelKeyDeletion(ctx, &sdkkms.CancelKeyDeletionInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	described, err := c.DescribeKey(ctx, &sdkkms.DescribeKeyInput{KeyId: k.KeyId})
	if err != nil || described.KeyMetadata.KeyState != types.KeyStateDisabled || described.KeyMetadata.DeletionDate != nil || aws.ToString(described.KeyMetadata.Description) != "updated" {
		t.Fatalf("after cancel: %+v, %v", described, err)
	}
	if _, err := c.ScheduleKeyDeletion(ctx, &sdkkms.ScheduleKeyDeletionInput{KeyId: k.KeyId, PendingWindowInDays: aws.Int32(7)}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(8 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	_, err = c.DescribeKey(ctx, &sdkkms.DescribeKeyInput{KeyId: k.KeyId})
	requireCode(t, err, "NotFoundException")
}

func TestSDKAuthenticatedEncryptionAndReEncryption(t *testing.T) {
	s := New()
	c := sdkClient(t, s, rootMetadata("111122223333", "us-east-1", "aws"))
	ctx := context.Background()
	k1, k2 := createSDKKey(t, c), createSDKKey(t, c)
	if _, err := c.CreateAlias(ctx, &sdkkms.CreateAliasInput{AliasName: aws.String("alias/source"), TargetKeyId: k1.KeyId}); err != nil {
		t.Fatal(err)
	}
	plain := []byte{0, 255, 1, 2, 3, 4}
	contextA := map[string]string{"purpose": "test", "name": "日本語"}
	one, err := c.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: aws.String("alias/source"), Plaintext: plain, EncryptionContext: contextA})
	if err != nil {
		t.Fatal(err)
	}
	two, err := c.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k1.Arn, Plaintext: plain, EncryptionContext: contextA})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(one.CiphertextBlob, two.CiphertextBlob) || bytes.Contains(one.CiphertextBlob, plain) || aws.ToString(one.KeyId) != aws.ToString(k1.Arn) {
		t.Fatal("encryption failed randomness, opacity, or canonical key ID")
	}
	decoded, err := c.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: one.CiphertextBlob, KeyId: k1.KeyId, EncryptionContext: map[string]string{"name": "日本語", "purpose": "test"}})
	if err != nil || !bytes.Equal(decoded.Plaintext, plain) {
		t.Fatalf("decrypt = %+v, %v", decoded, err)
	}
	for _, contextB := range []map[string]string{nil, {"purpose": "TEST", "name": "日本語"}, {"purpose": "test", "name": "日本語", "extra": ""}} {
		_, err = c.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: one.CiphertextBlob, EncryptionContext: contextB})
		var invalid *types.InvalidCiphertextException
		if !errors.As(err, &invalid) {
			t.Fatalf("context mismatch: %v", err)
		}
	}
	tampered := slices.Clone(one.CiphertextBlob)
	tampered[len(tampered)-1] ^= 1
	_, err = c.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: tampered, EncryptionContext: contextA})
	requireCode(t, err, "InvalidCiphertextException")
	_, err = c.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: one.CiphertextBlob, KeyId: k2.KeyId, EncryptionContext: contextA})
	requireCode(t, err, "IncorrectKeyException")
	contextB := map[string]string{"purpose": "destination"}
	reencrypted, err := c.ReEncrypt(ctx, &sdkkms.ReEncryptInput{CiphertextBlob: one.CiphertextBlob, SourceKeyId: k1.Arn, SourceEncryptionContext: contextA, DestinationKeyId: k2.Arn, DestinationEncryptionContext: contextB})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(reencrypted.SourceKeyId) != aws.ToString(k1.Arn) || aws.ToString(reencrypted.KeyId) != aws.ToString(k2.Arn) {
		t.Fatalf("reencrypt key IDs: %+v", reencrypted)
	}
	decoded, err = c.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: reencrypted.CiphertextBlob, EncryptionContext: contextB})
	if err != nil || !bytes.Equal(decoded.Plaintext, plain) {
		t.Fatalf("re-encryption data loss: %+v, %v", decoded, err)
	}
	_, err = c.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: k1.KeyId, Plaintext: plain, DryRun: aws.Bool(true)})
	requireCode(t, err, "DryRunOperationException")
}

func TestSDKDataKeys(t *testing.T) {
	c := sdkClient(t, New(), rootMetadata("111122223333", "us-east-1", "aws"))
	ctx := context.Background()
	k := createSDKKey(t, c)
	context := map[string]string{"aws:sqs:queuearn": "arn:aws:sqs:us-east-1:111122223333:queue"}
	for _, spec := range []types.DataKeySpec{types.DataKeySpecAes128, types.DataKeySpecAes256} {
		out, err := c.GenerateDataKey(ctx, &sdkkms.GenerateDataKeyInput{KeyId: k.Arn, KeySpec: spec, EncryptionContext: context})
		if err != nil {
			t.Fatal(err)
		}
		size := 32
		if spec == types.DataKeySpecAes128 {
			size = 16
		}
		if len(out.Plaintext) != size {
			t.Fatalf("data key size = %d", len(out.Plaintext))
		}
		decoded, err := c.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: out.CiphertextBlob, EncryptionContext: context})
		if err != nil || !bytes.Equal(out.Plaintext, decoded.Plaintext) {
			t.Fatalf("data key decrypt: %v", err)
		}
	}
	out, err := c.GenerateDataKeyWithoutPlaintext(ctx, &sdkkms.GenerateDataKeyWithoutPlaintextInput{KeyId: k.KeyId, NumberOfBytes: aws.Int32(47), EncryptionContext: context})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := c.Decrypt(ctx, &sdkkms.DecryptInput{CiphertextBlob: out.CiphertextBlob, EncryptionContext: context})
	if err != nil || len(decoded.Plaintext) != 47 {
		t.Fatalf("without plaintext decrypt: %+v, %v", decoded, err)
	}
	_, err = c.GenerateDataKey(ctx, &sdkkms.GenerateDataKeyInput{KeyId: k.KeyId})
	requireCode(t, err, "ValidationException")
	_, err = c.GenerateDataKey(ctx, &sdkkms.GenerateDataKeyInput{KeyId: k.KeyId, KeySpec: types.DataKeySpecAes256, NumberOfBytes: aws.Int32(32)})
	requireCode(t, err, "ValidationException")
	random, err := c.GenerateRandom(ctx, &sdkkms.GenerateRandomInput{NumberOfBytes: aws.Int32(23)})
	if err != nil || len(random.Plaintext) != 23 {
		t.Fatalf("random: %+v, %v", random, err)
	}
}

func TestSDKDecryptIgnoreCiphertextAuthorizesWithoutDecrypting(t *testing.T) {
	c := sdkClient(t, New(), rootMetadata("111122223333", "us-east-1", "aws"))
	ctx := t.Context()
	key := createSDKKey(t, c)
	function := "arn:aws:lambda:us-east-1:111122223333:function:durable"
	encryption := map[string]string{"aws:lambda:FunctionArn": function}
	modifiers := []types.DryRunModifierType{types.DryRunModifierTypeIgnoreCiphertext}
	for _, blob := range [][]byte{nil, []byte("not a ciphertext")} {
		_, err := c.Decrypt(ctx, &sdkkms.DecryptInput{KeyId: key.Arn, CiphertextBlob: blob, EncryptionContext: encryption, DryRun: aws.Bool(true), DryRunModifiers: modifiers})
		requireCode(t, err, "DryRunOperationException")
	}
	_, err := c.Decrypt(ctx, &sdkkms.DecryptInput{DryRun: aws.Bool(true), DryRunModifiers: modifiers})
	requireCode(t, err, "ValidationException")
	encrypted, err := c.Encrypt(ctx, &sdkkms.EncryptInput{KeyId: key.Arn, EncryptionContext: encryption, Plaintext: []byte("durable protected data")})
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range [][]byte{[]byte("not a ciphertext"), encrypted.CiphertextBlob} {
		_, err = c.Decrypt(ctx, &sdkkms.DecryptInput{KeyId: key.Arn, CiphertextBlob: blob, EncryptionContext: encryption, DryRun: aws.Bool(false), DryRunModifiers: modifiers})
		requireCode(t, err, "ValidationException")
	}
	_, err = c.Decrypt(ctx, &sdkkms.DecryptInput{KeyId: key.Arn, CiphertextBlob: []byte("not a ciphertext"), DryRun: aws.Bool(true)})
	requireCode(t, err, "InvalidCiphertextException")
	admin := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"}]}`
	denied := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:EncryptionContext:aws:lambda:FunctionArn":"` + function + `"}}}]}`
	if _, err = c.PutKeyPolicy(ctx, &sdkkms.PutKeyPolicyInput{KeyId: key.Arn, PolicyName: aws.String("default"), Policy: aws.String(denied)}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Decrypt(ctx, &sdkkms.DecryptInput{KeyId: key.Arn, EncryptionContext: encryption, DryRun: aws.Bool(true), DryRunModifiers: modifiers})
	requireCode(t, err, "AccessDeniedException")
	if _, err = c.PutKeyPolicy(ctx, &sdkkms.PutKeyPolicyInput{KeyId: key.Arn, PolicyName: aws.String("default"), Policy: aws.String(admin)}); err != nil {
		t.Fatal(err)
	}
	decrypted, err := c.Decrypt(ctx, &sdkkms.DecryptInput{KeyId: key.Arn, CiphertextBlob: encrypted.CiphertextBlob, EncryptionContext: encryption})
	if err != nil || !bytes.Equal(decrypted.Plaintext, []byte("durable protected data")) {
		t.Fatalf("real decrypt after permission restoration: %v %v", decrypted, err)
	}
	if _, err = c.DisableKey(ctx, &sdkkms.DisableKeyInput{KeyId: key.Arn}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Decrypt(ctx, &sdkkms.DecryptInput{KeyId: key.Arn, EncryptionContext: encryption, DryRun: aws.Bool(true), DryRunModifiers: modifiers})
	requireCode(t, err, "DisabledException")
}
