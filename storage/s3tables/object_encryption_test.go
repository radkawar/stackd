package s3tables

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	"stackd/internal/awschecksum"
	"stackd/internal/awswire"
	domain "stackd/internal/services/s3tables"
	"stackd/storage/internal/s3tablescrypt"
	"stackd/storage/memory"
)

func TestMemoryRetainsOnlyAuthenticatedCiphertext(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryObjects(memory.NewDomain()).(*memoryObjects)
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	warehouse, key := "s3://warehouse", "metadata/native.json"
	plain := []byte("private native metadata and object payload")
	if err := r.Write(ctx, warehouse, key, plain, now); err != nil {
		t.Fatal(err)
	}
	var original warehouseObject
	if err := r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if err := tx.Check(false); err != nil {
			return err
		}
		original = s.objects[warehouse][key]
		if bytes.Equal(original.data.Data, plain) || bytes.Contains(original.data.Data, plain) || original.data.Version != 1 || original.data.Algorithm != "AES256-GCM" || len(original.data.Key) != 32 || len(original.data.Nonce) != 12 {
			t.Fatal("memory retained plaintext or an invalid cipher envelope")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	info, err := domain.SingleObjectInfo(key, plain, domain.ObjectAttributes{}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.WriteObject(ctx, warehouse, plain, info, domain.ObjectConditions{}, nil)
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != "PreconditionFailed" {
		t.Fatalf("identical object replacement = %v", err)
	}
	denied := errors.New("revoked publication")
	deniedInfo := info
	deniedInfo.Key = "denied-publication"
	guardCalls := 0
	if _, err = r.WriteObject(ctx, warehouse, plain, deniedInfo, domain.ObjectConditions{}, func(context.Context) error {
		guardCalls++
		if guardCalls == 2 {
			return denied
		}
		return nil
	}); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if guardCalls != 2 {
		t.Fatalf("publication guard calls = %d, want precondition and precommit checks", guardCalls)
	}
	if _, err := r.Info(ctx, warehouse, deniedInfo.Key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("guard failure published destination: %v", err)
	}
	if err = r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if !bytes.Equal(s.objects[warehouse][key].data.Data, original.data.Data) {
			t.Fatal("guard rollback replaced ciphertext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ warehouse, key string }{{warehouse, "other-key"}, {"s3://other-warehouse", key}} {
		if err = r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
			copied := original
			copied.info.Key = target.key
			putMemoryObject(s, target.warehouse, copied)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if data, _, err := r.ReadObject(ctx, target.warehouse, target.key); err == nil || data != nil {
			t.Fatal("swapped object ciphertext was readable")
		}
	}
	if err = r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		broken := original
		broken.data.Data = bytes.Clone(original.data.Data)
		broken.data.Data[len(broken.data.Data)-1] ^= 1
		putMemoryObject(s, warehouse, broken)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if data, _, err := r.ReadObject(ctx, warehouse, key); !errors.Is(err, s3tablescrypt.ErrEnvelope) || data != nil {
		t.Fatalf("tampered object did not fail closed: %q %v", data, err)
	}
	_, err = r.WriteObject(ctx, warehouse, plain, info, domain.ObjectConditions{}, nil)
	if !errors.As(err, &wire) || wire.Code != "PreconditionFailed" {
		t.Fatalf("overwrite read corrupt old bytes instead of rejecting existence: %v", err)
	}
}

func TestMemoryMultipartCiphertextAndIdentity(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryObjects(memory.NewDomain()).(*memoryObjects)
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	upload := domain.MultipartUpload{Warehouse: "s3://warehouse", Key: "object", ID: "upload", Created: now}
	if err := r.CreateMultipart(ctx, upload, nil); err != nil {
		t.Fatal(err)
	}
	plain := []byte("private staged multipart data")
	checksum, err := awschecksum.Sum("CRC64NVME", plain)
	if err != nil {
		t.Fatal(err)
	}
	checksums := domain.ObjectChecksums{CRC64NVME: checksum}
	info, err := domain.SingleObjectInfo(upload.Key, plain, domain.ObjectAttributes{ChecksumAlgorithm: "CRC64NVME", Checksums: checksums}, now)
	if err != nil {
		t.Fatal(err)
	}
	part := domain.MultipartPart{Number: 1, ETag: info.ETag, Size: info.Size, Modified: now, Checksums: checksums}
	if err = r.UploadMultipartPart(ctx, upload.Warehouse, upload.Key, upload.ID, part, plain, nil); err != nil {
		t.Fatal(err)
	}
	uKey := uploadKey{upload.Warehouse, upload.Key, upload.ID}
	var original warehousePart
	if err = r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		original = s.uploads[uKey].parts[1]
		if bytes.Equal(original.data.Data, plain) || bytes.Contains(original.data.Data, plain) || len(original.data.Data) != len(plain)+16 || len(original.data.Key) != 32 || len(original.data.Nonce) != 12 || original.info.Checksums != checksums || original.info.Size != int64(len(plain)) {
			t.Fatal("memory retained a plaintext staged part")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		warehouse, key, id string
		number             int
	}{
		{upload.Warehouse, upload.Key, "other-upload", 1},
		{upload.Warehouse, upload.Key, upload.ID, 2},
		{"s3://other", upload.Key, upload.ID, 1},
		{upload.Warehouse, "other-key", upload.ID, 1},
	} {
		if _, err = original.data.Open(nil, s3tablescrypt.PartIdentity(target.warehouse, target.key, target.id, int64(target.number)), original.info.Size); err == nil {
			t.Fatal("part identity was not authenticated")
		}
	}
	denied := errors.New("revoked publication")
	selected := []domain.CompletedPart{{Number: 1, ETag: part.ETag}}
	guardCalls := 0
	if _, err = r.CompleteMultipart(ctx, upload.Warehouse, upload.Key, upload.ID, selected, now, domain.ObjectConditions{}, domain.ObjectChecksums{}, func(context.Context) error {
		guardCalls++
		if guardCalls == 2 {
			return denied
		}
		return nil
	}); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if guardCalls != 2 {
		t.Fatalf("publication guard calls = %d, want precondition and precommit checks", guardCalls)
	}
	if _, err := r.Info(ctx, upload.Warehouse, upload.Key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("guard failure published destination: %v", err)
	}
	if err = r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		if !bytes.Equal(s.uploads[uKey].parts[1].data.Data, original.data.Data) {
			t.Fatal("failed completion changed staged ciphertext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// An unselected corrupted part must not be decrypted or block completion.
	if err = r.store.Update(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		u := s.uploads[uKey]
		u.parts = maps.Clone(u.parts)
		u.parts[2] = warehousePart{info: domain.MultipartPart{Number: 2}, data: s3tablescrypt.Envelope{}}
		s.uploads[uKey] = u
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.CompleteMultipart(ctx, upload.Warehouse, upload.Key, upload.ID, selected, now, domain.ObjectConditions{}, domain.ObjectChecksums{}, nil); err != nil {
		t.Fatal(err)
	}
	actual, completed, err := r.ReadObject(ctx, upload.Warehouse, upload.Key)
	if err != nil || !bytes.Equal(actual, plain) || completed.Size != int64(len(plain)) || completed.Attributes.ChecksumAlgorithm != "CRC64NVME" || completed.Attributes.Checksums != checksums {
		t.Fatalf("completed bytes: %q %#v %v", actual, completed, err)
	}
	if err = r.store.View(ctx, func(s *warehouseState, tx *memory.Transaction) error {
		object := s.objects[upload.Warehouse][upload.Key]
		if bytes.Equal(object.data.Data, plain) || bytes.Equal(object.data.Key, original.data.Key) || len(object.data.Data) != len(plain)+16 || object.info.Attributes.Checksums != checksums {
			t.Fatal("completion did not re-encrypt under a fresh object key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
