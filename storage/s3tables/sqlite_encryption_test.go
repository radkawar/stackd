package s3tables_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	owner "stackd/internal/services/s3tables"
	"stackd/storage/sqlite"
	tablesql "stackd/storage/sqlite/s3tables"
)

type physicalEnvelope struct {
	content    []byte
	version    int64
	algorithm  string
	key, nonce []byte
}

func objectEnvelope(t *testing.T, db *sql.DB, warehouse, key string) physicalEnvelope {
	t.Helper()
	var e physicalEnvelope
	if err := db.QueryRow("SELECT content, encryption_version, encryption_algorithm, encryption_key, encryption_nonce FROM s3tables_objects WHERE warehouse = ? AND object_key = ?", warehouse, key).Scan(&e.content, &e.version, &e.algorithm, &e.key, &e.nonce); err != nil {
		t.Fatal(err)
	}
	return e
}
func partEnvelope(t *testing.T, db *sql.DB, warehouse, key, id string, number int) physicalEnvelope {
	t.Helper()
	var e physicalEnvelope
	if err := db.QueryRow("SELECT content, encryption_version, encryption_algorithm, encryption_key, encryption_nonce FROM s3tables_multipart_parts WHERE warehouse = ? AND object_key = ? AND upload_id = ? AND part_number = ?", warehouse, key, id, number).Scan(&e.content, &e.version, &e.algorithm, &e.key, &e.nonce); err != nil {
		t.Fatal(err)
	}
	return e
}
func encryptedEnvelope(t *testing.T, e physicalEnvelope, plain []byte) {
	t.Helper()
	if e.version != 1 || e.algorithm != "AES256-GCM" || len(e.key) != 32 || len(e.nonce) != 12 || len(e.content) != len(plain)+16 || bytes.Equal(e.content, plain) || len(plain) != 0 && bytes.Contains(e.content, plain) {
		t.Fatalf("invalid retained ciphertext: version=%d algorithm=%q key=%d nonce=%d content=%d plaintext=%d", e.version, e.algorithm, len(e.key), len(e.nonce), len(e.content), len(plain))
	}
}
func sameEnvelope(a, b physicalEnvelope) bool {
	return a.version == b.version && a.algorithm == b.algorithm && bytes.Equal(a.content, b.content) && bytes.Equal(a.key, b.key) && bytes.Equal(a.nonce, b.nonce)
}
func execPhysical(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteObjectsCiphertextIdentityTamperingAndReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "encrypted.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	objects := sqliteObjects(t, ctx, db)
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	warehouse, key := "s3://warehouse", "metadata/current.json"
	plain := []byte("private retained object contents")
	if err = objects.Write(ctx, warehouse, key, plain, now); err != nil {
		t.Fatal(err)
	}
	original := objectEnvelope(t, db, warehouse, key)
	encryptedEnvelope(t, original, plain)
	info, err := owner.SingleObjectInfo(key, plain, owner.ObjectAttributes{}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = objects.WriteObject(ctx, warehouse, plain, info, owner.ObjectConditions{}, nil)
	physicalCode(t, err, "PreconditionFailed")
	if !sameEnvelope(original, objectEnvelope(t, db, warehouse, key)) {
		t.Fatal("rejected identical write replaced retained encryption")
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
	actual, reopened, err := objects.ReadObject(ctx, warehouse, key)
	if err != nil || !bytes.Equal(actual, plain) || reopened.ETag != info.ETag || reopened.Size != int64(len(plain)) || !sameEnvelope(original, objectEnvelope(t, db, warehouse, key)) {
		t.Fatalf("durable encrypted read changed plaintext metadata: %q %#v %v", actual, reopened, err)
	}
	for _, target := range []struct{ warehouse, key string }{{warehouse, "another-key"}, {"s3://other-warehouse", key}} {
		if err = objects.Write(ctx, target.warehouse, target.key, plain, now); err != nil {
			t.Fatal(err)
		}
		execPhysical(t, db, "UPDATE s3tables_objects SET content=?, encryption_version=?, encryption_algorithm=?, encryption_key=?, encryption_nonce=? WHERE warehouse=? AND object_key=?", original.content, original.version, original.algorithm, original.key, original.nonce, target.warehouse, target.key)
		if actual, _, err = objects.ReadObject(ctx, target.warehouse, target.key); err == nil || actual != nil {
			t.Fatal("object envelope swapping bypassed identity authentication")
		}
	}
	corruptTag := bytes.Clone(original.content)
	corruptTag[len(corruptTag)-1] ^= 1
	for _, mutation := range []struct {
		name, clause string
		value        any
	}{
		{"tag", "content=?", corruptTag},
		{"truncated", "content=?", []byte("bad")},
		{"algorithm", "encryption_algorithm=?", "unsupported"},
		{"version", "encryption_version=?", int64(999)},
		{"key", "encryption_key=?", []byte("bad")},
		{"nonce", "encryption_nonce=?", []byte("bad")},
		{"size", "size=?", int64(len(plain) + 1)},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			execPhysical(t, db, "UPDATE s3tables_objects SET content=?, encryption_version=?, encryption_algorithm=?, encryption_key=?, encryption_nonce=?, size=? WHERE warehouse=? AND object_key=?", original.content, original.version, original.algorithm, original.key, original.nonce, info.Size, warehouse, key)
			execPhysical(t, db, "UPDATE s3tables_objects SET "+mutation.clause+" WHERE warehouse=? AND object_key=?", mutation.value, warehouse, key)
			if data, _, err := objects.ReadObject(ctx, warehouse, key); err == nil || data != nil {
				t.Fatalf("malformed encrypted state returned bytes: %q %v", data, err)
			}
			// Normal reopen does not decrypt retained BLOBs, but cannot make an
			// invalid encrypted envelope readable or treat it as legacy plaintext.
			reopened := sqliteObjects(t, ctx, db)
			if data, _, err := reopened.ReadObject(ctx, warehouse, key); err == nil || data != nil {
				t.Fatal("reopen introduced a plaintext fallback")
			}
			_, err = objects.WriteObject(ctx, warehouse, plain, info, owner.ObjectConditions{}, nil)
			physicalCode(t, err, "PreconditionFailed")
		})
	}
	// Plaintext inserted after adapter exposure is not a read fallback.
	execPhysical(t, db, "UPDATE s3tables_objects SET content=?, size=?, encryption_version=0, encryption_algorithm='', encryption_key=X'', encryption_nonce=X'' WHERE warehouse=? AND object_key=?", plain, len(plain), warehouse, key)
	if data, _, err := objects.ReadObject(ctx, warehouse, key); err == nil || data != nil {
		t.Fatal("read exposed an unmigrated plaintext row")
	}
}

func TestSQLiteMultipartCiphertextIdentityAndGuardRollback(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "parts.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	objects := sqliteObjects(t, ctx, db)
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	upload := owner.MultipartUpload{Warehouse: "s3://warehouse", Key: "object", ID: "source", Created: now}
	if err = objects.CreateMultipart(ctx, upload, nil); err != nil {
		t.Fatal(err)
	}
	plain := []byte("private staged multipart data")
	part := physicalPart(t, 1, plain, now)
	if err = objects.UploadMultipartPart(ctx, upload.Warehouse, upload.Key, upload.ID, part, plain, nil); err != nil {
		t.Fatal(err)
	}
	original := partEnvelope(t, db, upload.Warehouse, upload.Key, upload.ID, 1)
	encryptedEnvelope(t, original, plain)
	selected := []owner.CompletedPart{{Number: 1, ETag: part.ETag, Checksums: part.Checksums}}
	denied := errors.New("publication revoked")
	if err = objects.UploadMultipartPart(ctx, upload.Warehouse, upload.Key, upload.ID, part, plain, func(context.Context) error { return denied }); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if !sameEnvelope(original, partEnvelope(t, db, upload.Warehouse, upload.Key, upload.ID, 1)) {
		t.Fatal("failed part guard changed retained ciphertext")
	}
	guardCalls := 0
	if _, err = objects.CompleteMultipart(ctx, upload.Warehouse, upload.Key, upload.ID, selected, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, func(context.Context) error {
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
	if !sameEnvelope(original, partEnvelope(t, db, upload.Warehouse, upload.Key, upload.ID, 1)) {
		t.Fatal("failed completion guard changed staged ciphertext")
	}
	if _, err := objects.Info(ctx, upload.Warehouse, upload.Key); !errors.Is(err, owner.ErrNotFound) {
		t.Fatalf("failed completion guard published destination: %v", err)
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
		if target.id != upload.ID || target.warehouse != upload.Warehouse || target.key != upload.Key {
			if err = objects.CreateMultipart(ctx, owner.MultipartUpload{Warehouse: target.warehouse, Key: target.key, ID: target.id, Created: now}, nil); err != nil {
				t.Fatal(err)
			}
		}
		targetPart := part
		targetPart.Number = target.number
		if err = objects.UploadMultipartPart(ctx, target.warehouse, target.key, target.id, targetPart, plain, nil); err != nil {
			t.Fatal(err)
		}
		execPhysical(t, db, "UPDATE s3tables_multipart_parts SET content=?, encryption_version=?, encryption_algorithm=?, encryption_key=?, encryption_nonce=? WHERE warehouse=? AND object_key=? AND upload_id=? AND part_number=?", original.content, original.version, original.algorithm, original.key, original.nonce, target.warehouse, target.key, target.id, target.number)
		if _, err = objects.CompleteMultipart(ctx, target.warehouse, target.key, target.id, []owner.CompletedPart{{Number: target.number, ETag: part.ETag, Checksums: part.Checksums}}, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, nil); err == nil {
			t.Fatal("swapped staged part was accepted")
		}
		if _, _, err = objects.ListMultipartParts(ctx, target.warehouse, target.key, target.id); err != nil {
			t.Fatal("failed authentication consumed upload")
		}
	}
	corruptTag := bytes.Clone(original.content)
	corruptTag[len(corruptTag)-1] ^= 1
	for _, mutation := range []struct {
		name, clause string
		value        any
	}{
		{"tag", "content=?", corruptTag},
		{"version", "encryption_version=?", int64(999)},
		{"nonce", "encryption_nonce=?", []byte("bad")},
		{"size", "size=?", part.Size + 1},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			execPhysical(t, db, "UPDATE s3tables_multipart_parts SET content=?, encryption_version=?, encryption_algorithm=?, encryption_key=?, encryption_nonce=?, size=? WHERE warehouse=? AND object_key=? AND upload_id=? AND part_number=1", original.content, original.version, original.algorithm, original.key, original.nonce, part.Size, upload.Warehouse, upload.Key, upload.ID)
			execPhysical(t, db, "UPDATE s3tables_multipart_parts SET "+mutation.clause+" WHERE warehouse=? AND object_key=? AND upload_id=? AND part_number=1", mutation.value, upload.Warehouse, upload.Key, upload.ID)
			if _, err := objects.CompleteMultipart(ctx, upload.Warehouse, upload.Key, upload.ID, selected, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, nil); err == nil {
				t.Fatal("malformed staged encryption was accepted")
			}
			if _, err := objects.Info(ctx, upload.Warehouse, upload.Key); !errors.Is(err, owner.ErrNotFound) {
				t.Fatalf("failed part authentication published destination: %v", err)
			}
			if _, _, err := objects.ListMultipartParts(ctx, upload.Warehouse, upload.Key, upload.ID); err != nil {
				t.Fatal("failed part authentication consumed upload")
			}
		})
	}
	execPhysical(t, db, "UPDATE s3tables_multipart_parts SET content=?, encryption_version=?, encryption_algorithm=?, encryption_key=?, encryption_nonce=?, size=? WHERE warehouse=? AND object_key=? AND upload_id=? AND part_number=1", original.content, original.version, original.algorithm, original.key, original.nonce, part.Size, upload.Warehouse, upload.Key, upload.ID)
	// Part 2 is deliberately corrupt but unselected: completion reads only part 1.
	if _, err = objects.CompleteMultipart(ctx, upload.Warehouse, upload.Key, upload.ID, selected, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, nil); err != nil {
		t.Fatal(err)
	}
	completed := objectEnvelope(t, db, upload.Warehouse, upload.Key)
	encryptedEnvelope(t, completed, plain)
	if bytes.Equal(completed.key, original.key) {
		t.Fatal("assembled object reused staged encryption key")
	}
	actual, info, err := objects.ReadObject(ctx, upload.Warehouse, upload.Key)
	if err != nil || !bytes.Equal(actual, plain) || info.Size != int64(len(plain)) {
		t.Fatalf("completion plaintext semantics changed: %q %#v %v", actual, info, err)
	}
}

func TestSQLiteLegacyEncryptionMigrationIsEagerAtomicAndDurable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	warehouse, key := "s3://legacy", "metadata/historical.json"
	plain := []byte("historical private metadata retained before encryption")
	info, err := owner.SingleObjectInfo(key, plain, owner.ObjectAttributes{ContentType: "application/json", CacheControl: "private"}, now)
	if err != nil {
		t.Fatal(err)
	}
	execPhysical(t, db, "INSERT INTO s3tables_objects (warehouse,object_key,etag,size,modified_at,content,content_type,cache_control) VALUES (?,?,?,?,?,?,?,?)", warehouse, key, info.ETag, info.Size, now, plain, info.Attributes.ContentType, info.Attributes.CacheControl)
	// A native initial metadata row and an ordinary empty object are legacy too.
	execPhysical(t, db, "INSERT INTO s3tables_objects (warehouse,object_key,etag,size,modified_at,content) VALUES (?,?,?,?,?,?)", warehouse, "metadata/native.json", info.ETag, info.Size, now, plain)
	emptyInfo, err := owner.SingleObjectInfo("empty", nil, owner.ObjectAttributes{}, now)
	if err != nil {
		t.Fatal(err)
	}
	execPhysical(t, db, "INSERT INTO s3tables_objects (warehouse,object_key,etag,size,modified_at,content) VALUES (?,?,?,?,?,?)", warehouse, "empty", emptyInfo.ETag, 0, now, []byte{})
	execPhysical(t, db, "INSERT INTO s3tables_multipart_uploads (warehouse,object_key,upload_id,created_at,content_type,cache_control,content_disposition,content_encoding,content_language,checksum_algorithm) VALUES (?,?,?,?,?,?,?,?,?,?)", warehouse, "pending", "legacy-upload", now, "application/parquet", "private", "", "", "", "")
	part := physicalPart(t, 1, plain, now)
	execPhysical(t, db, "INSERT INTO s3tables_multipart_parts (warehouse,object_key,upload_id,part_number,etag,size,modified_at,checksum_crc32,checksum_crc32c,checksum_sha1,checksum_sha256,content,encryption_algorithm) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", warehouse, "pending", "legacy-upload", 1, part.ETag, part.Size, now, "", "", "", part.Checksums.SHA256, plain, "malformed-marker")
	// Malformed version-zero envelopes cannot be mistaken for plaintext. Objects
	// converted earlier in the same transaction must remain entirely unpublished.
	if adapter, err := tablesql.NewObjects(ctx, db); err == nil || adapter != nil {
		t.Fatal("malformed migration exposed an adapter")
	}
	legacy := objectEnvelope(t, db, warehouse, key)
	if legacy.version != 0 || !bytes.Equal(legacy.content, plain) {
		t.Fatal("failed migration partially published converted objects")
	}
	execPhysical(t, db, "UPDATE s3tables_multipart_parts SET encryption_algorithm='', size=size+1")
	if adapter, err := tablesql.NewObjects(ctx, db); err == nil || adapter != nil {
		t.Fatal("mismatched legacy size was silently rewritten")
	}
	execPhysical(t, db, "UPDATE s3tables_multipart_parts SET size=size-1")
	execPhysical(t, db, "CREATE TRIGGER reject_part_encryption BEFORE UPDATE OF content ON s3tables_multipart_parts BEGIN SELECT RAISE(ABORT, 'migration write denied'); END")
	if adapter, err := tablesql.NewObjects(ctx, db); err == nil || adapter != nil {
		t.Fatal("failed migration write exposed an adapter")
	}
	if legacy = objectEnvelope(t, db, warehouse, key); legacy.version != 0 || !bytes.Equal(legacy.content, plain) {
		t.Fatal("migration write failure partially published object encryption")
	}
	execPhysical(t, db, "DROP TRIGGER reject_part_encryption")
	objects := sqliteObjects(t, ctx, db)
	for _, objectKey := range []string{key, "metadata/native.json", "empty"} {
		data := plain
		if objectKey == "empty" {
			data = []byte{}
		}
		encryptedEnvelope(t, objectEnvelope(t, db, warehouse, objectKey), data)
	}
	encryptedEnvelope(t, partEnvelope(t, db, warehouse, "pending", "legacy-upload", 1), plain)
	actual, retained, err := objects.ReadObject(ctx, warehouse, key)
	if err != nil || !bytes.Equal(actual, plain) || retained.ETag != info.ETag || retained.Size != info.Size || retained.Attributes != info.Attributes {
		t.Fatalf("migration changed historical metadata: %q %#v %v", actual, retained, err)
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
	actual, retained, err = objects.ReadObject(ctx, warehouse, key)
	if err != nil || !bytes.Equal(actual, plain) || retained.ETag != info.ETag {
		t.Fatalf("migrated history lost on reopen: %q %#v %v", actual, retained, err)
	}
	_, err = objects.WriteObject(ctx, warehouse, plain, info, owner.ObjectConditions{}, nil)
	physicalCode(t, err, "PreconditionFailed")
	if _, err = objects.CompleteMultipart(ctx, warehouse, "pending", "legacy-upload", []owner.CompletedPart{{Number: 1, ETag: part.ETag}}, now, owner.ObjectConditions{}, owner.ObjectChecksums{}, nil); err != nil {
		t.Fatalf("legacy part did not survive migration/reopen: %v", err)
	}
	actual, _, err = objects.ReadObject(ctx, warehouse, "pending")
	if err != nil || !bytes.Equal(actual, plain) {
		t.Fatalf("migrated multipart bytes: %q %v", actual, err)
	}
}
