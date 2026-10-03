package kms

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd/internal/awsctx"
)

func TestStorageCopiesRollbackAndReplacement(t *testing.T) {
	ctx := context.Background()
	backend := NewMemoryStorage(nil)
	s := NewWithStorage(backend, nil)
	sc := rootMetadata("111122223333", "us-east-1", "aws")
	c := sdkClient(t, s, sc)
	k := createSDKKey(t, c)
	if _, err := c.CreateAlias(ctx, &sdkkms.CreateAliasInput{AliasName: aws.String("alias/durable"), TargetKeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	root := awsctx.WithMetadata(ctx, sc)
	ciphertext, _, err := s.Encrypt(root, aws.ToString(k.KeyId), []byte("preserve key material"), nil)
	if err != nil {
		t.Fatal(err)
	}
	scope := StorageScope{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}
	if err := backend.View(ctx, func(tx Reader) error {
		keys, err := tx.Keys(scope)
		if err != nil {
			return err
		}
		set, err := tx.KeySet(KeyOwner{Partition: scope.Partition, AccountID: scope.AccountID}, keys[0].ID)
		if err != nil {
			return err
		}
		clear(set.Materials[0].Material)
		keys[0].Description = "must not escape a read"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	replacement := NewWithStorage(backend, nil)
	plain, _, err := replacement.Decrypt(root, ciphertext, nil)
	if err != nil || !bytes.Equal(plain, []byte("preserve key material")) {
		t.Fatalf("replacement lost key material: %q, %v", plain, err)
	}
	c2 := sdkClient(t, replacement, sc)
	out, apiErr := c2.DescribeKey(ctx, &sdkkms.DescribeKeyInput{KeyId: aws.String("alias/durable")})
	if apiErr != nil || aws.ToString(out.KeyMetadata.Description) != "test key" {
		t.Fatalf("storage copy escaped: %+v, %v", out, apiErr)
	}
	failing := NewWithStorage(failWrites{Storage: backend}, nil)
	cf := sdkClient(t, failing, sc)
	_, apiErr = cf.TagResource(ctx, &sdkkms.TagResourceInput{KeyId: k.KeyId, Tags: []types.Tag{{TagKey: aws.String("rolled"), TagValue: aws.String("back")}}})
	requireCode(t, apiErr, "KMSInternalException")
	tags, apiErr := c2.ListResourceTags(ctx, &sdkkms.ListResourceTagsInput{KeyId: k.KeyId})
	if apiErr != nil || len(tags.Tags) != 0 {
		t.Fatalf("failed transaction committed: %+v, %v", tags, apiErr)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := backend.Transact(canceled, func(Transaction) error { t.Fatal("canceled transaction called callback"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transaction: %v", err)
	}
}

type failWrites struct{ Storage }

func (s failWrites) Transact(ctx context.Context, fn func(Transaction) error) error {
	return s.Storage.Transact(ctx, func(tx Transaction) error { return fn(failWriteTransaction{Transaction: tx}) })
}

func (s failWrites) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return s.Storage.Attempt(ctx, func(tx Transaction) error { return fn(failWriteTransaction{Transaction: tx}) })
}

type failWriteTransaction struct{ Transaction }

func (tx failWriteTransaction) PutKey(sc StorageScope, k KeyRecord) error {
	if err := tx.Transaction.PutKey(sc, k); err != nil {
		return err
	}
	return errors.New("injected write failure after tentative mutation")
}
