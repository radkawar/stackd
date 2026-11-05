package s3tables_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	owner "stackd/internal/services/s3tables"
	"stackd/storage/memory"
	storage "stackd/storage/s3tables"
	"stackd/storage/sqlite"
	tablesql "stackd/storage/sqlite/s3tables"
)

func TestPhysicalObjectsCreateOnlyAndRetainClonedMetadata(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			var objects owner.WarehouseObjects
			if backend == "memory" {
				objects = storage.NewMemoryObjects(memory.NewDomain())
			} else {
				db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "info.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				objects, err = tablesql.NewObjects(ctx, db)
				if err != nil {
					t.Fatal(err)
				}
			}
			now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
			expires := now.Add(time.Hour)
			data := []byte("stored payload")
			checksums := physicalCRC64(data)
			info, err := owner.SingleObjectInfo("data/object", data, owner.ObjectAttributes{ContentType: "application/parquet", Expires: &expires, ChecksumAlgorithm: "CRC64NVME", Checksums: checksums}, now)
			if err != nil {
				t.Fatal(err)
			}
			const warehouse = "s3://private--table-s3"
			if _, err = objects.WriteObject(ctx, warehouse, data, info, owner.ObjectConditions{}, nil); err != nil {
				t.Fatal(err)
			}
			got, err := objects.Info(ctx, warehouse, info.Key)
			if err != nil || got.Key != info.Key || got.Size != int64(len(data)) || got.ETag != info.ETag || !got.Modified.Equal(now) || got.Attributes.ContentType != info.Attributes.ContentType || got.Attributes.ChecksumAlgorithm != "CRC64NVME" || got.Attributes.Checksums != checksums || got.Attributes.Expires == nil || !got.Attributes.Expires.Equal(expires) {
				t.Fatalf("Info = %#v, %v", got, err)
			}
			*got.Attributes.Expires = now
			got, err = objects.Info(ctx, warehouse, info.Key)
			if err != nil || got.Attributes.Expires == nil || !got.Attributes.Expires.Equal(expires) {
				t.Fatalf("Info attributes aliased persisted metadata: %#v, %v", got, err)
			}
			changedAttributes := owner.CloneObjectAttributes(info.Attributes)
			changedAttributes.ContentType = "application/octet-stream"
			changedAttributes.CacheControl = "public"
			for _, tc := range []struct {
				name       string
				data       []byte
				attributes owner.ObjectAttributes
				conditions owner.ObjectConditions
			}{
				{"identical", data, info.Attributes, owner.ObjectConditions{}},
				{"metadata-only", data, changedAttributes, owner.ObjectConditions{}},
				{"different-bytes", []byte("replacement bytes"), owner.ObjectAttributes{}, owner.ObjectConditions{}},
				{"if-none-match", data, info.Attributes, owner.ObjectConditions{IfNoneMatch: "*"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					candidate, err := owner.SingleObjectInfo(info.Key, tc.data, tc.attributes, now)
					if err != nil {
						t.Fatal(err)
					}
					_, err = objects.WriteObject(ctx, warehouse, tc.data, candidate, tc.conditions, nil)
					physicalCode(t, err, "PreconditionFailed")
					actual, retained, err := objects.ReadObject(ctx, warehouse, info.Key)
					if err != nil || !bytes.Equal(actual, data) || retained.ETag != info.ETag || retained.Size != info.Size || !retained.Modified.Equal(info.Modified) || retained.Attributes.ContentType != info.Attributes.ContentType || retained.Attributes.CacheControl != info.Attributes.CacheControl || retained.Attributes.Checksums != checksums || retained.Attributes.Expires == nil || !retained.Attributes.Expires.Equal(expires) {
						t.Fatalf("rejected overwrite changed retained object: %q %#v %v", actual, retained, err)
					}
				})
			}
			denied := errors.New("publication authorization revoked")
			_, err = objects.WriteObject(ctx, warehouse, data, info, owner.ObjectConditions{}, func(context.Context) error { return denied })
			if !errors.Is(err, denied) {
				t.Fatalf("existing destination masked revoked authority: %v", err)
			}
			if _, err = objects.Info(ctx, warehouse, "missing"); !errors.Is(err, owner.ErrNotFound) {
				t.Fatalf("missing Info = %v", err)
			}
			if _, err = objects.Info(ctx, "s3://other--table-s3", info.Key); !errors.Is(err, owner.ErrNotFound) {
				t.Fatalf("cross-warehouse Info = %v", err)
			}
		})
	}
}
