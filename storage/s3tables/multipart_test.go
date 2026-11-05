package s3tables_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc64"
	"path/filepath"
	"testing"
	"time"

	"stackd/internal/awswire"
	owner "stackd/internal/services/s3tables"
	"stackd/storage/memory"
	storage "stackd/storage/s3tables"
	"stackd/storage/sqlite"
	tablesql "stackd/storage/sqlite/s3tables"
)

func sqliteObjects(t *testing.T, ctx context.Context, db *sql.DB) owner.WarehouseObjects {
	t.Helper()
	objects, err := tablesql.NewObjects(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	return objects
}

func physicalPart(t *testing.T, number int, data []byte, modified time.Time) owner.MultipartPart {
	t.Helper()
	sum := sha256.Sum256(data)
	checksums := owner.ObjectChecksums{SHA256: base64.StdEncoding.EncodeToString(sum[:])}
	info, err := owner.SingleObjectInfo("object", data, owner.ObjectAttributes{ChecksumAlgorithm: "SHA256", Checksums: checksums}, modified)
	if err != nil {
		t.Fatal(err)
	}
	return owner.MultipartPart{Number: number, ETag: info.ETag, Size: info.Size, Modified: info.Modified, Checksums: checksums}
}
func physicalCode(t *testing.T, err error, want string) {
	t.Helper()
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}
func TestPhysicalMultipartAtomicPublicationAndCleanup(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			var objects owner.WarehouseObjects
			if backend == "memory" {
				objects = storage.NewMemoryObjects(memory.NewDomain())
			} else {
				db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "parts.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				objects = sqliteObjects(t, ctx, db)
			}
			now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
			warehouse, key := "s3://private--table-s3", "data/object"
			old := []byte("previous destination")
			if err := objects.Write(ctx, warehouse, key, old, now); err != nil {
				t.Fatal(err)
			}
			_, oldInfo, err := objects.ReadObject(ctx, warehouse, key)
			if err != nil {
				t.Fatal(err)
			}
			expires := now.Add(time.Hour)
			singleInfo, err := owner.SingleObjectInfo("data/attributes", old, owner.ObjectAttributes{ContentType: "text/plain", CacheControl: "private", Expires: &expires}, now)
			if err != nil {
				t.Fatal(err)
			}
			returned, err := objects.WriteObject(ctx, warehouse, old, singleInfo, owner.ObjectConditions{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			*returned.Attributes.Expires = now.Add(24 * time.Hour)
			_, persisted, err := objects.ReadObject(ctx, warehouse, singleInfo.Key)
			if err != nil || persisted.Attributes.Expires == nil || !persisted.Attributes.Expires.Equal(expires) || persisted.Attributes.ContentType != "text/plain" || persisted.Attributes.CacheControl != "private" {
				t.Fatalf("ordinary write attributes changed through returned value: %#v %v", persisted, err)
			}
			upload := owner.MultipartUpload{ID: "first", Warehouse: warehouse, Key: key, Created: now, Attributes: owner.ObjectAttributes{ContentType: "application/parquet", CacheControl: "max-age=60", ContentDisposition: "attachment", ContentLanguage: "en", Expires: &expires, ChecksumAlgorithm: "SHA256"}}
			if err = objects.CreateMultipart(ctx, upload, nil); err != nil {
				t.Fatal(err)
			}
			data := []byte("actual multipart BLOB bytes")
			replaced := []byte("superseded staged bytes")
			replacedPart := physicalPart(t, 1, replaced, now.Add(-time.Minute))
			if err = objects.UploadMultipartPart(ctx, warehouse, key, upload.ID, replacedPart, replaced, nil); err != nil {
				t.Fatal(err)
			}
			part := physicalPart(t, 1, data, now)
			if err = objects.UploadMultipartPart(ctx, warehouse, key, upload.ID, part, data, nil); err != nil {
				t.Fatal(err)
			}
			// Every accepted read must own its metadata and byte slices.
			readUpload, parts, err := objects.ListMultipartParts(ctx, warehouse, key, upload.ID)
			if err != nil || len(parts) != 1 {
				t.Fatalf("list: %#v %v", parts, err)
			}
			*readUpload.Attributes.Expires = now.Add(24 * time.Hour)
			parts[0].ETag = "mutated"
			readUpload, parts, err = objects.ListMultipartParts(ctx, warehouse, key, upload.ID)
			if err != nil || parts[0].ETag != part.ETag || !readUpload.Attributes.Expires.Equal(expires) {
				t.Fatal("caller mutated persisted upload")
			}
			selected := []owner.CompletedPart{{Number: 1, ETag: part.ETag, Checksums: part.Checksums}}
			_, err = objects.CompleteMultipart(ctx, warehouse, key, upload.ID, selected, now, owner.ObjectConditions{IfNoneMatch: "*"}, owner.ObjectChecksums{}, nil)
			physicalCode(t, err, "PreconditionFailed")
			denied := errors.New("publication authorization revoked")
			_, err = objects.CompleteMultipart(ctx, warehouse, key, upload.ID, selected, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, nil)
			physicalCode(t, err, "PreconditionFailed")
			_, err = objects.CompleteMultipart(ctx, warehouse, key, upload.ID, selected, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, func(context.Context) error { return denied })
			if !errors.Is(err, denied) {
				t.Fatalf("existing destination masked revoked authority: %v", err)
			}
			err = objects.AbortMultipart(ctx, warehouse, key, upload.ID, func(context.Context) error { return denied })
			if !errors.Is(err, denied) {
				t.Fatalf("abort guard failure lost: %v", err)
			}
			deniedUpload := upload
			deniedUpload.ID = "denied-initiation"
			err = objects.CreateMultipart(ctx, deniedUpload, func(context.Context) error { return denied })
			if !errors.Is(err, denied) {
				t.Fatalf("initiation guard failure lost: %v", err)
			}
			_, err = objects.GetMultipartUpload(ctx, warehouse, key, deniedUpload.ID)
			physicalCode(t, err, "NoSuchUpload")
			actual, info, err := objects.ReadObject(ctx, warehouse, key)
			if err != nil || !bytes.Equal(actual, old) || info.ETag != oldInfo.ETag {
				t.Fatalf("failed completion changed destination: %#v %q %v", info, actual, err)
			}
			_, parts, err = objects.ListMultipartParts(ctx, warehouse, key, upload.ID)
			if err != nil || len(parts) != 1 {
				t.Fatalf("failed completion or abort consumed upload: %#v %v", parts, err)
			}
			// A successful publication needs a new key; the rejected upload above
			// remains available with its original parts.
			key = "data/new-object"
			upload.Key, upload.ID = key, "new-destination"
			if err = objects.CreateMultipart(ctx, upload, nil); err != nil {
				t.Fatal(err)
			}
			if err = objects.UploadMultipartPart(ctx, warehouse, key, upload.ID, part, data, nil); err != nil {
				t.Fatal(err)
			}
			_, err = objects.CompleteMultipart(ctx, warehouse, key, upload.ID, selected, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, func(context.Context) error { return denied })
			if !errors.Is(err, denied) {
				t.Fatalf("guard failure lost: %v", err)
			}
			if _, err = objects.Info(ctx, warehouse, key); !errors.Is(err, owner.ErrNotFound) {
				t.Fatalf("guard failure published destination: %v", err)
			}
			_, parts, err = objects.ListMultipartParts(ctx, warehouse, key, upload.ID)
			if err != nil || len(parts) != 1 || parts[0] != part {
				t.Fatalf("guard failure consumed upload: %#v %v", parts, err)
			}
			completed, err := objects.CompleteMultipart(ctx, warehouse, key, upload.ID, selected, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			partMD5 := md5.Sum(data)
			multipartMD5 := md5.Sum(partMD5[:])
			wantETag := "\"" + hex.EncodeToString(multipartMD5[:]) + "-1\""
			partSHA := sha256.Sum256(data)
			composite := sha256.Sum256(partSHA[:])
			wantChecksum := base64.StdEncoding.EncodeToString(composite[:]) + "-1"
			actual, info, err = objects.ReadObject(ctx, warehouse, key)
			if err != nil || !bytes.Equal(actual, data) || info.ETag != wantETag || completed.ETag != info.ETag || info.Attributes.Checksums.SHA256 != wantChecksum || info.Attributes.ContentType != upload.Attributes.ContentType || info.Attributes.CacheControl != upload.Attributes.CacheControl || info.Attributes.Expires == nil || !info.Attributes.Expires.Equal(expires) {
				t.Fatalf("completed record mismatch: %#v %q %v", info, actual, err)
			}
			actual[0] = '!'
			*info.Attributes.Expires = now.Add(48 * time.Hour)
			actual, info, err = objects.ReadObject(ctx, warehouse, key)
			if err != nil || !bytes.Equal(actual, data) || !info.Attributes.Expires.Equal(expires) {
				t.Fatal("caller mutated completed object")
			}
			_, _, err = objects.ListMultipartParts(ctx, warehouse, key, upload.ID)
			physicalCode(t, err, "NoSuchUpload")
			if err = objects.UploadMultipartPart(ctx, warehouse, key, upload.ID, part, data, nil); err == nil {
				t.Fatal("late upload recreated completed parts")
			}
			// Cleanup must also remove uploads with no parts and warehouses with no
			// completed objects, not merely loop over the completed object listing.
			pending := owner.MultipartUpload{ID: "pending", Warehouse: "s3://pending--table-s3", Key: "pending", Created: now}
			if err = objects.CreateMultipart(ctx, pending, nil); err != nil {
				t.Fatal(err)
			}
			if err = objects.UploadMultipartPart(ctx, pending.Warehouse, pending.Key, pending.ID, part, data, nil); err != nil {
				t.Fatal(err)
			}
			empty := pending
			empty.ID = "empty"
			if err = objects.CreateMultipart(ctx, empty, nil); err != nil {
				t.Fatal(err)
			}
			if err = objects.PurgeWarehouse(ctx, pending.Warehouse); err != nil {
				t.Fatal(err)
			}
			_, _, err = objects.ListMultipartParts(ctx, pending.Warehouse, pending.Key, pending.ID)
			physicalCode(t, err, "NoSuchUpload")
			_, _, err = objects.ListMultipartParts(ctx, empty.Warehouse, empty.Key, empty.ID)
			physicalCode(t, err, "NoSuchUpload")
			if _, _, err = objects.ReadObject(ctx, warehouse, key); err != nil {
				t.Fatalf("cleanup crossed warehouse boundary: %v", err)
			}
		})
	}
}
func TestSQLiteMultipartStateAndAttributesSurviveReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "durable-parts.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	upload := owner.MultipartUpload{ID: "durable", Warehouse: "s3://durable--table-s3", Key: "object", Created: now, Attributes: owner.ObjectAttributes{ChecksumAlgorithm: "SHA256", ContentType: "application/parquet", ContentDisposition: "inline", ContentLanguage: "en", ContentEncoding: "gzip", CacheControl: "immutable", Expires: &expires}}
	objects := sqliteObjects(t, ctx, db)
	if err = objects.CreateMultipart(ctx, upload, nil); err != nil {
		t.Fatal(err)
	}
	data := []byte("restart-safe physical bytes")
	part := physicalPart(t, 1, data, now)
	if err = objects.UploadMultipartPart(ctx, upload.Warehouse, upload.Key, upload.ID, part, data, nil); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	objects = sqliteObjects(t, ctx, db)
	reopened, parts, err := objects.ListMultipartParts(ctx, upload.Warehouse, upload.Key, upload.ID)
	if err != nil || reopened.ID != upload.ID || len(parts) != 1 || parts[0] != part || reopened.Attributes.ContentEncoding != "gzip" || reopened.Attributes.Expires == nil || !reopened.Attributes.Expires.Equal(expires) {
		t.Fatalf("reopened multipart record lost: %#v %#v %v", reopened, parts, err)
	}
	completed, err := objects.CompleteMultipart(ctx, upload.Warehouse, upload.Key, upload.ID, []owner.CompletedPart{{Number: 1, ETag: part.ETag, Checksums: part.Checksums}}, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	objects = sqliteObjects(t, ctx, db)
	actual, info, err := objects.ReadObject(ctx, upload.Warehouse, upload.Key)
	if err != nil || !bytes.Equal(actual, data) || info.ETag != completed.ETag || info.Attributes.Checksums != completed.Attributes.Checksums || info.Attributes.Expires == nil || !info.Attributes.Expires.Equal(expires) {
		t.Fatalf("reopened completion lost: %#v %q %v", info, actual, err)
	}
	_, _, err = objects.ListMultipartParts(ctx, upload.Warehouse, upload.Key, upload.ID)
	physicalCode(t, err, "NoSuchUpload")
	var count int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM s3tables_multipart_parts").Scan(&count); err != nil || count != 0 {
		t.Fatalf("completion retained part BLOBs: %d %v", count, err)
	}
}

func physicalCRC64(data []byte) owner.ObjectChecksums {
	var sum [8]byte
	binary.BigEndian.PutUint64(sum[:], crc64.Checksum(data, crc64.MakeTable(0x9a6c9329ac4bc9b5)))
	return owner.ObjectChecksums{CRC64NVME: base64.StdEncoding.EncodeToString(sum[:])}
}

func physicalCRC64Part(t *testing.T, number int, data []byte, modified time.Time) owner.MultipartPart {
	t.Helper()
	checksums := physicalCRC64(data)
	info, err := owner.SingleObjectInfo("object", data, owner.ObjectAttributes{ChecksumAlgorithm: "CRC64NVME", Checksums: checksums}, modified)
	if err != nil {
		t.Fatal(err)
	}
	return owner.MultipartPart{Number: number, ETag: info.ETag, Size: info.Size, Modified: info.Modified, Checksums: checksums}
}

func TestPhysicalCRC64MultipartFullObjectAndAtomicErrors(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, algorithm := range []string{"", "CRC64NVME"} {
			t.Run(backend+"/init="+algorithm, func(t *testing.T) {
				ctx := context.Background()
				var objects owner.WarehouseObjects
				var db *sql.DB
				if backend == "memory" {
					objects = storage.NewMemoryObjects(memory.NewDomain())
				} else {
					var err error
					db, err = sqlite.Open(ctx, filepath.Join(t.TempDir(), "crc64.sqlite"))
					if err != nil {
						t.Fatal(err)
					}
					defer db.Close()
					objects = sqliteObjects(t, ctx, db)
				}
				now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
				upload := owner.MultipartUpload{ID: "native", Warehouse: "s3://crc64--table-s3", Key: "data/object", Created: now, Attributes: owner.ObjectAttributes{ChecksumAlgorithm: algorithm, ContentType: "application/parquet"}}
				old := []byte("old destination must survive all rejected completions")
				if err := objects.Write(ctx, upload.Warehouse, upload.Key, old, now); err != nil {
					t.Fatal(err)
				}
				oldInfo, err := objects.Info(ctx, upload.Warehouse, upload.Key)
				if err != nil {
					t.Fatal(err)
				}
				if err := objects.CreateMultipart(ctx, upload, nil); err != nil {
					t.Fatal(err)
				}
				first := bytes.Repeat([]byte("a"), int(owner.MultipartMinimumPartSize))
				last := []byte("the actual selected final plaintext")
				unselected := []byte("not part of the final object")
				parts := make([]owner.MultipartPart, 3)
				for i, data := range [][]byte{first, last, unselected} {
					parts[i] = physicalCRC64Part(t, i+1, data, now)
					if err := objects.UploadMultipartPart(ctx, upload.Warehouse, upload.Key, upload.ID, parts[i], data, nil); err != nil {
						t.Fatal(err)
					}
				}
				all := append(bytes.Clone(first), last...)
				expected := physicalCRC64(all)
				size := int64(len(all))
				selected := []owner.CompletedPart{{Number: 1, ETag: parts[0].ETag, Checksums: parts[0].Checksums}, {Number: 2, ETag: parts[1].ETag}}
				badSelected := append([]owner.CompletedPart(nil), selected...)
				badSelected[1].Checksums = parts[0].Checksums
				var oldCipher, firstCipher physicalEnvelope
				if db != nil {
					oldCipher = objectEnvelope(t, db, upload.Warehouse, upload.Key)
					firstCipher = partEnvelope(t, db, upload.Warehouse, upload.Key, upload.ID, 1)
					encryptedEnvelope(t, firstCipher, first)
				}
				assertUnchanged := func(t *testing.T) {
					t.Helper()
					actual, info, err := objects.ReadObject(ctx, upload.Warehouse, upload.Key)
					if err != nil || !bytes.Equal(actual, old) || info.ETag != oldInfo.ETag {
						t.Fatalf("rejected completion changed destination: %#v, %v", info, err)
					}
					reopened, retained, err := objects.ListMultipartParts(ctx, upload.Warehouse, upload.Key, upload.ID)
					if err != nil || reopened.Attributes.ChecksumAlgorithm != algorithm || len(retained) != len(parts) {
						t.Fatalf("rejected completion consumed upload: %#v, %v", retained, err)
					}
					for i := range parts {
						if retained[i] != parts[i] {
							t.Fatalf("rejected completion changed part: %#v", retained[i])
						}
					}
					if db != nil && (!sameEnvelope(oldCipher, objectEnvelope(t, db, upload.Warehouse, upload.Key)) || !sameEnvelope(firstCipher, partEnvelope(t, db, upload.Warehouse, upload.Key, upload.ID, 1))) {
						t.Fatal("rejected completion replaced retained encryption")
					}
				}
				for _, tc := range []struct {
					name       string
					conditions owner.ObjectConditions
					checksums  owner.ObjectChecksums
					selection  []owner.CompletedPart
					code       string
				}{
					{"full-digest", owner.ObjectConditions{}, parts[0].Checksums, selected, "BadDigest"},
					{"composite-digest", owner.ObjectConditions{}, owner.ObjectChecksums{CRC64NVME: expected.CRC64NVME + "-2"}, selected, "BadDigest"},
					{"part-digest", owner.ObjectConditions{}, owner.ObjectChecksums{}, badSelected, "InvalidPart"},
					{"composite-type", owner.ObjectConditions{ChecksumType: "COMPOSITE"}, owner.ObjectChecksums{}, selected, "InvalidRequest"},
				} {
					t.Run(tc.name, func(t *testing.T) {
						_, err := objects.CompleteMultipart(ctx, upload.Warehouse, upload.Key, upload.ID, tc.selection, now, tc.conditions, tc.checksums, nil)
						physicalCode(t, err, tc.code)
						assertUnchanged(t)
					})
				}
				_, err = objects.CompleteMultipart(ctx, upload.Warehouse, upload.Key, upload.ID, selected, now, owner.ObjectConditions{ChecksumType: "FULL_OBJECT"}, expected, nil)
				physicalCode(t, err, "PreconditionFailed")
				assertUnchanged(t)
				fresh := upload
				fresh.Key, fresh.ID = "data/new-object", "native-fresh"
				if err := objects.CreateMultipart(ctx, fresh, nil); err != nil {
					t.Fatal(err)
				}
				for i, data := range [][]byte{first, last, unselected} {
					if err := objects.UploadMultipartPart(ctx, fresh.Warehouse, fresh.Key, fresh.ID, parts[i], data, nil); err != nil {
						t.Fatal(err)
					}
				}
				denied := errors.New("publication revoked")
				_, err = objects.CompleteMultipart(ctx, fresh.Warehouse, fresh.Key, fresh.ID, selected, now, owner.ObjectConditions{ChecksumType: "FULL_OBJECT"}, expected, func(context.Context) error { return denied })
				if !errors.Is(err, denied) {
					t.Fatalf("publication guard = %v", err)
				}
				if _, err := objects.Info(ctx, fresh.Warehouse, fresh.Key); !errors.Is(err, owner.ErrNotFound) {
					t.Fatalf("guard failure published destination: %v", err)
				}
				_, retained, err := objects.ListMultipartParts(ctx, fresh.Warehouse, fresh.Key, fresh.ID)
				if err != nil || len(retained) != len(parts) {
					t.Fatalf("guard failure consumed parts: %#v, %v", retained, err)
				}
				assertUnchanged(t)
				// No per-part checksums are required in the full-object manifest.
				for i := range selected {
					selected[i].Checksums = owner.ObjectChecksums{}
				}
				supplied := expected
				if algorithm == "" {
					supplied = owner.ObjectChecksums{}
				}
				completed, err := objects.CompleteMultipart(ctx, fresh.Warehouse, fresh.Key, fresh.ID, selected, now, owner.ObjectConditions{ChecksumType: "FULL_OBJECT"}, supplied, nil)
				if err != nil || completed.Size != size || completed.Attributes.ChecksumAlgorithm != "CRC64NVME" || completed.Attributes.Checksums != expected {
					t.Fatalf("full object completion = %#v, %v", completed, err)
				}
				actual, info, err := objects.ReadObject(ctx, fresh.Warehouse, fresh.Key)
				if err != nil || !bytes.Equal(actual, all) || info.Size != size || info.Attributes.Checksums != expected {
					t.Fatalf("full object read = %#v, %v", info, err)
				}
				info, err = objects.Info(ctx, fresh.Warehouse, fresh.Key)
				if err != nil || info.Attributes.Checksums != expected || info.Size != size {
					t.Fatalf("full object Info = %#v, %v", info, err)
				}
				listed, err := objects.List(ctx, fresh.Warehouse, fresh.Key)
				if err != nil || len(listed) != 1 || listed[0].Attributes.Checksums != expected || listed[0].Size != size {
					t.Fatalf("full object list = %#v, %v", listed, err)
				}
				_, _, err = objects.ListMultipartParts(ctx, fresh.Warehouse, fresh.Key, fresh.ID)
				physicalCode(t, err, "NoSuchUpload")
				if db != nil {
					encryptedEnvelope(t, objectEnvelope(t, db, fresh.Warehouse, fresh.Key), all)
					var storedChecksum string
					var storedSize int64
					if err := db.QueryRowContext(ctx, "SELECT checksum_crc64nvme, size FROM s3tables_objects WHERE warehouse=? AND object_key=?", fresh.Warehouse, fresh.Key).Scan(&storedChecksum, &storedSize); err != nil || storedChecksum != expected.CRC64NVME || storedSize != size {
						t.Fatalf("typed full object metadata = %q, %d, %v", storedChecksum, storedSize, err)
					}
					var count int
					if err := db.QueryRowContext(ctx, "SELECT count(*) FROM s3tables_multipart_parts WHERE warehouse=? AND object_key=? AND upload_id=?", fresh.Warehouse, fresh.Key, fresh.ID).Scan(&count); err != nil || count != 0 {
						t.Fatalf("successful completion retained parts: %d, %v", count, err)
					}
				}
				assertUnchanged(t)
			})
		}
	}
}

func TestSQLiteCRC64TypedStateReopenAndMetadataOnlyInfo(t *testing.T) {
	for _, algorithm := range []string{"", "CRC64NVME"} {
		t.Run("init="+algorithm, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "durable-crc64.sqlite")
			db, err := sqlite.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
			upload := owner.MultipartUpload{ID: "durable-crc64", Warehouse: "s3://durable--table-s3", Key: "object", Created: now, Attributes: owner.ObjectAttributes{ChecksumAlgorithm: algorithm}}
			objects := sqliteObjects(t, ctx, db)
			if err := objects.CreateMultipart(ctx, upload, nil); err != nil {
				t.Fatal(err)
			}
			data := []byte("123456789")
			part := physicalCRC64Part(t, 1, data, now)
			if part.Checksums.CRC64NVME != "rosUhgp5mIg=" {
				t.Fatalf("native CRC64 vector = %#v", part.Checksums)
			}
			if err := objects.UploadMultipartPart(ctx, upload.Warehouse, upload.Key, upload.ID, part, data, nil); err != nil {
				t.Fatal(err)
			}
			var typed, kind string
			if err := db.QueryRowContext(ctx, "SELECT checksum_crc64nvme, typeof(checksum_crc64nvme) FROM s3tables_multipart_parts").Scan(&typed, &kind); err != nil || typed != part.Checksums.CRC64NVME || kind != "text" {
				t.Fatalf("typed part CRC64 = %q, %q, %v", typed, kind, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = sqlite.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			objects = sqliteObjects(t, ctx, db)
			reopened, retained, err := objects.ListMultipartParts(ctx, upload.Warehouse, upload.Key, upload.ID)
			if err != nil || reopened.Attributes.ChecksumAlgorithm != algorithm || len(retained) != 1 || retained[0] != part {
				t.Fatalf("CRC64 part reopen = %#v, %#v, %v", reopened, retained, err)
			}
			_, err = objects.CompleteMultipart(ctx, upload.Warehouse, upload.Key, upload.ID, []owner.CompletedPart{{Number: 1, ETag: part.ETag}}, now, owner.ObjectConditions{ChecksumType: "FULL_OBJECT"}, part.Checksums, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = sqlite.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			objects = sqliteObjects(t, ctx, db)
			actual, info, err := objects.ReadObject(ctx, upload.Warehouse, upload.Key)
			if err != nil || !bytes.Equal(actual, data) || info.Size != 9 || info.Attributes.ChecksumAlgorithm != "CRC64NVME" || info.Attributes.Checksums != part.Checksums {
				t.Fatalf("CRC64 object reopen = %q, %#v, %v", actual, info, err)
			}
			encryptedEnvelope(t, objectEnvelope(t, db, upload.Warehouse, upload.Key), data)
			// Info and listing must keep typed checksums without authenticating or
			// retrieving the encrypted body, even after reopening the adapter.
			execPhysical(t, db, "UPDATE s3tables_objects SET content=X'00' WHERE warehouse=? AND object_key=?", upload.Warehouse, upload.Key)
			objects = sqliteObjects(t, ctx, db)
			info, err = objects.Info(ctx, upload.Warehouse, upload.Key)
			if err != nil || info.Size != 9 || info.Attributes.ChecksumAlgorithm != "CRC64NVME" || info.Attributes.Checksums != part.Checksums {
				t.Fatalf("metadata-only CRC64 Info = %#v, %v", info, err)
			}
			listed, err := objects.List(ctx, upload.Warehouse, "")
			if err != nil || len(listed) != 1 || listed[0].Attributes.Checksums != part.Checksums {
				t.Fatalf("metadata-only CRC64 list = %#v, %v", listed, err)
			}
			if _, _, err := objects.ReadObject(ctx, upload.Warehouse, upload.Key); err == nil {
				t.Fatal("corrupt encrypted body became readable through metadata lookup")
			}
		})
	}
}

func TestPhysicalCompetingMultipartCompletionsPublishOnlyOnce(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			var objects owner.WarehouseObjects
			if backend == "memory" {
				objects = storage.NewMemoryObjects(memory.NewDomain())
			} else {
				db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "competing.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				objects = sqliteObjects(t, ctx, db)
			}
			now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
			const warehouse, key = "s3://competing--table-s3", "data/object"
			uploads := []owner.MultipartUpload{
				{Warehouse: warehouse, Key: key, ID: "first", Created: now, Attributes: owner.ObjectAttributes{ChecksumAlgorithm: "CRC64NVME", CacheControl: "max-age=60"}},
				{Warehouse: warehouse, Key: key, ID: "second", Created: now, Attributes: owner.ObjectAttributes{ChecksumAlgorithm: "CRC64NVME", CacheControl: "max-age=120"}},
			}
			payloads := [][]byte{[]byte("first competing payload"), []byte("second competing payload")}
			parts := make([]owner.MultipartPart, len(uploads))
			for i, upload := range uploads {
				if err := objects.CreateMultipart(ctx, upload, nil); err != nil {
					t.Fatal(err)
				}
				parts[i] = physicalCRC64Part(t, 1, payloads[i], now)
				if err := objects.UploadMultipartPart(ctx, warehouse, key, upload.ID, parts[i], payloads[i], nil); err != nil {
					t.Fatal(err)
				}
			}
			type result struct {
				index int
				info  owner.ObjectInfo
				err   error
			}
			start := make(chan struct{})
			results := make(chan result, len(uploads))
			for i, upload := range uploads {
				go func(index int, upload owner.MultipartUpload) {
					<-start
					selected := []owner.CompletedPart{{Number: 1, ETag: parts[index].ETag, Checksums: parts[index].Checksums}}
					info, err := objects.CompleteMultipart(ctx, warehouse, key, upload.ID, selected, now, owner.ObjectConditions{ChecksumType: "FULL_OBJECT"}, parts[index].Checksums, nil)
					results <- result{index: index, info: info, err: err}
				}(i, upload)
			}
			close(start)
			winner, loser := -1, -1
			var published owner.ObjectInfo
			for range uploads {
				result := <-results
				if result.err == nil {
					if winner != -1 {
						t.Fatal("both competing completions published")
					}
					winner, published = result.index, result.info
				} else {
					physicalCode(t, result.err, "PreconditionFailed")
					loser = result.index
				}
			}
			if winner == -1 || loser == -1 {
				t.Fatalf("competing completions: winner=%d loser=%d", winner, loser)
			}
			data, info, err := objects.ReadObject(ctx, warehouse, key)
			if err != nil || !bytes.Equal(data, payloads[winner]) || info.ETag != published.ETag || info.Attributes.Checksums != parts[winner].Checksums || info.Attributes.CacheControl != uploads[winner].Attributes.CacheControl {
				t.Fatalf("winner publication changed: %q %#v %v", data, info, err)
			}
			_, _, err = objects.ListMultipartParts(ctx, warehouse, key, uploads[winner].ID)
			physicalCode(t, err, "NoSuchUpload")
			retained, staged, err := objects.ListMultipartParts(ctx, warehouse, key, uploads[loser].ID)
			if err != nil || retained.ID != uploads[loser].ID || len(staged) != 1 || staged[0] != parts[loser] {
				t.Fatalf("losing completion consumed its upload: %#v %#v %v", retained, staged, err)
			}
			selected := []owner.CompletedPart{{Number: 1, ETag: parts[loser].ETag}}
			_, err = objects.CompleteMultipart(ctx, warehouse, key, uploads[loser].ID, selected, now.Add(time.Hour), owner.ObjectConditions{}, parts[loser].Checksums, nil)
			physicalCode(t, err, "PreconditionFailed")
			data, info, err = objects.ReadObject(ctx, warehouse, key)
			if err != nil || !bytes.Equal(data, payloads[winner]) || info.ETag != published.ETag || !info.Modified.Equal(published.Modified) || info.Attributes.CacheControl != uploads[winner].Attributes.CacheControl {
				t.Fatalf("loser retry changed publication: %q %#v %v", data, info, err)
			}
			_, staged, err = objects.ListMultipartParts(ctx, warehouse, key, uploads[loser].ID)
			if err != nil || len(staged) != 1 || staged[0] != parts[loser] {
				t.Fatalf("loser retry consumed its parts: %#v %v", staged, err)
			}
		})
	}
}
