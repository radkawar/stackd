package s3_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/internal/awstest"
	"stackd/storage/s3"
	"stackd/storage/sqlite"
	sqls3 "stackd/storage/sqlite/s3"
)

func forVersionRepositories(t *testing.T, run func(*testing.T, s3.Repository)) {
	t.Helper()
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "memory" {
				run(t, s3.NewMemory(nil))
				return
			}
			db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "s3.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			run(t, sqls3.New(db))
		})
	}
}

func versionBucket() s3.BucketRecord {
	return s3.BucketRecord{Key: s3.BucketKey{Partition: "aws", Name: "history"}, AccountID: "111111111111", Region: "us-east-1", Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Versioning: "Enabled"}
}

func TestVersionHistoryOrderingMarkersAndNullReplacement(t *testing.T) {
	forVersionRepositories(t, func(t *testing.T, repo s3.Repository) {
		bucket := versionBucket()
		key := s3.ObjectKey{Bucket: bucket.Key, Name: "a/日本"}
		var firstSequence int64
		if err := repo.Update(t.Context(), func(tx s3.Transaction) error {
			if err := tx.PutBucket(bucket); err != nil {
				return err
			}
			for _, v := range []s3.ObjectRecord{
				{Key: key, Modified: bucket.Created, Metadata: map[string]string{"old": "removed"}},
				{Key: key, VersionID: "version-one", Sequence: 9000, Modified: bucket.Created.Add(-time.Hour)},
				{Key: key, VersionID: "null", Modified: bucket.Created},
				{Key: key, VersionID: "marker", DeleteMarker: true, Modified: bucket.Created},
				{Key: s3.ObjectKey{Bucket: bucket.Key, Name: "b"}, VersionID: "other", Modified: bucket.Created},
			} {
				if _, err := tx.PutObject(v, []byte(v.VersionID)); err != nil {
					return err
				}
			}
			current, err := tx.Object(key)
			if err != nil || !current.DeleteMarker || current.VersionID != "marker" {
				t.Fatalf("current marker: %+v %v", current, err)
			}
			listed, err := tx.Objects(s3.ObjectQuery{Bucket: bucket.Key, Limit: 20})
			if err != nil || len(listed) != 1 || listed[0].Key.Name != "b" {
				t.Fatalf("marker-led current listing: %+v %v", listed, err)
			}
			history, err := tx.ObjectVersions(s3.VersionQuery{Bucket: bucket.Key, Prefix: "a/", Limit: 20})
			if err != nil || len(history) != 3 {
				t.Fatalf("history: %+v %v", history, err)
			}
			if history[0].VersionID != "marker" || history[1].VersionID != "null" || history[2].VersionID != "version-one" || !(history[0].Sequence > history[1].Sequence && history[1].Sequence > history[2].Sequence) {
				t.Fatalf("write order/null slot: %+v", history)
			}
			firstSequence = history[0].Sequence
			if len(history[1].Metadata) != 0 {
				t.Fatalf("null replacement retained metadata: %+v", history[1])
			}
			page, err := tx.ObjectVersions(s3.VersionQuery{Bucket: bucket.Key, AfterKey: key.Name, AfterVersion: "marker", Limit: 1})
			if err != nil || len(page) != 1 || page[0].VersionID != "null" {
				t.Fatalf("version cursor: %+v %v", page, err)
			}
			page, err = tx.ObjectVersions(s3.VersionQuery{Bucket: bucket.Key, AfterKey: key.Name, Limit: 10})
			if err != nil || len(page) != 1 || page[0].Key.Name != "b" {
				t.Fatalf("key-only cursor: %+v %v", page, err)
			}
			page, err = tx.ObjectVersions(s3.VersionQuery{Bucket: bucket.Key, AfterKey: key.Name, AfterVersion: "missing-version", Limit: 10})
			if err != nil || len(page) != 1 || page[0].Key.Name != "b" {
				t.Fatalf("missing version cursor repeated key: %+v %v", page, err)
			}
			if _, err := tx.DeleteObject(current.VersionKey()); err != nil {
				return err
			}
			current, err = tx.Object(key)
			if err != nil || current.VersionID != "null" {
				t.Fatalf("marker removal did not reveal null: %+v %v", current, err)
			}
			if _, err := tx.DeleteObject(current.VersionKey()); err != nil {
				return err
			}
			current, err = tx.Object(key)
			if err != nil || current.VersionID != "version-one" {
				t.Fatalf("null removal did not reveal immutable version: %+v %v", current, err)
			}
			_, err = tx.DeleteObject(current.VersionKey())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx s3.Transaction) error {
			if _, err := tx.PutObject(s3.ObjectRecord{Key: key, VersionID: "later", Modified: bucket.Created}, nil); err != nil {
				return err
			}
			current, err := tx.Object(key)
			if err != nil || current.Sequence <= firstSequence {
				t.Fatalf("sequence reused after deletion: %+v %v", current, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestImmutableVersionConflictAndTransactionRollback(t *testing.T) {
	forVersionRepositories(t, func(t *testing.T, repo s3.Repository) {
		bucket := versionBucket()
		key := s3.ObjectKey{Bucket: bucket.Key, Name: "object"}
		original := s3.ObjectRecord{Key: key, VersionID: "immutable", Modified: bucket.Created, Metadata: map[string]string{"state": "original"}, EncryptionKey: []byte{1, 2, 3}}
		if err := repo.Update(t.Context(), func(tx s3.Transaction) error {
			if err := tx.PutBucket(bucket); err != nil {
				return err
			}
			_, err := tx.PutObject(original, []byte("ciphertext"))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx s3.Transaction) error {
			bucket.Versioning = "Suspended"
			if err := tx.PutBucket(bucket); err != nil {
				return err
			}
			if _, err := tx.PutObject(s3.ObjectRecord{Key: key, VersionID: "null", Modified: bucket.Created}, []byte("rolled back")); err != nil {
				return err
			}
			original.Metadata = map[string]string{"state": "corrupt"}
			_, err := tx.PutObject(original, []byte("corrupt"))
			return err
		}); err == nil {
			t.Fatal("immutable overwrite committed")
		}
		abort := errors.New("abort deletion")
		if err := repo.Update(t.Context(), func(tx s3.Transaction) error {
			if _, err := tx.DeleteObject(original.VersionKey()); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatalf("rollback: %v", err)
		}
		if err := repo.View(t.Context(), func(r s3.Reader) error {
			stored, err := r.Bucket(bucket.Key)
			if err != nil || stored.Versioning != "Enabled" {
				t.Fatalf("failed transaction changed bucket: %+v %v", stored, err)
			}
			v, err := r.Object(key)
			if err != nil || v.VersionID != "immutable" || v.Metadata["state"] != "original" {
				t.Fatalf("failed transaction changed history: %+v %v", v, err)
			}
			data, err := r.ObjectData(v.VersionKey())
			if err != nil || len(data) != 1 || !bytes.Equal(data[0], []byte("ciphertext")) || !bytes.Equal(v.EncryptionKey, []byte{1, 2, 3}) {
				t.Fatalf("failed transaction changed encrypted data: %x %+v %v", data, v, err)
			}
			_, err = r.ObjectVersion(s3.ObjectVersionKey{ObjectKey: key, VersionID: "null"})
			if !errors.Is(err, s3.ErrNotFound) {
				t.Fatalf("rolled-back null survived: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestVersionValuesAreDetachedAndScopesRemainIsolated(t *testing.T) {
	forVersionRepositories(t, func(t *testing.T, repo s3.Repository) {
		bucket := versionBucket()
		key := s3.ObjectKey{Bucket: bucket.Key, Name: "object"}
		expires := bucket.Created.Add(time.Hour)
		v := s3.ObjectRecord{Key: key, VersionID: "shared-token", Modified: bucket.Created, Expires: &expires, Metadata: map[string]string{"m": "original"}, EncryptionKey: []byte{1, 2}}
		data := []byte{3, 4}
		if err := repo.Update(t.Context(), func(tx s3.Transaction) error {
			_, err := tx.PutObject(v, data)
			return err
		}); !errors.Is(err, s3.ErrNotFound) {
			t.Fatalf("orphan version accepted: %v", err)
		}
		if err := repo.Update(t.Context(), func(tx s3.Transaction) error {
			if err := tx.PutBucket(bucket); err != nil {
				return err
			}
			if _, err := tx.PutObject(v, data); err != nil {
				return err
			}
			other := bucket
			other.Key.Partition = "aws-cn"
			other.AccountID = "222222222222"
			if err := tx.PutBucket(other); err != nil {
				return err
			}
			copy := v
			copy.Key.Bucket = other.Key
			copy.Metadata = map[string]string{"m": "other"}
			if _, err := tx.PutObject(copy, []byte{9}); err != nil {
				return err
			}
			other.Key = s3.BucketKey{Partition: "aws", Name: "other-account"}
			if err := tx.PutBucket(other); err != nil {
				return err
			}
			copy.Key.Bucket = other.Key
			_, err := tx.PutObject(copy, []byte{8})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		v.Metadata["m"], v.EncryptionKey[0], data[0] = "mutated", 7, 7
		expires = expires.Add(time.Hour)
		for range 2 {
			if err := repo.View(t.Context(), func(r s3.Reader) error {
				stored, err := r.ObjectVersion(v.VersionKey())
				if err != nil || stored.Metadata["m"] != "original" || !stored.Expires.Equal(bucket.Created.Add(time.Hour)) || !bytes.Equal(stored.EncryptionKey, []byte{1, 2}) {
					t.Fatalf("aliased version: %+v %v", stored, err)
				}
				payload, err := r.ObjectData(v.VersionKey())
				if err != nil || len(payload) != 1 || !bytes.Equal(payload[0], []byte{3, 4}) {
					t.Fatalf("aliased payload: %x %v", payload, err)
				}
				stored.Metadata["m"], stored.EncryptionKey[0], payload[0][0] = "read-mutated", 5, 5
				payload[0] = []byte{6}
				*stored.Expires = bucket.Created
				history, err := r.ObjectVersions(s3.VersionQuery{Bucket: bucket.Key, Limit: 10})
				if err != nil || len(history) != 1 || history[0].Metadata["m"] != "original" || len(history[0].EncryptionKey) != 0 {
					t.Fatalf("history leaked scope/key: %+v %v", history, err)
				}
				history[0].Metadata["m"] = "listing-mutated"
				buckets, err := r.Buckets("aws", bucket.AccountID)
				if err != nil || len(buckets) != 1 || buckets[0].Key != bucket.Key {
					t.Fatalf("owner isolation: %+v %v", buckets, err)
				}
				otherKey := v.VersionKey()
				otherKey.Bucket.Partition = "aws-cn"
				other, err := r.ObjectData(otherKey)
				if err != nil || len(other) != 1 || !bytes.Equal(other[0], []byte{9}) {
					t.Fatalf("partition isolation: %x %v", other, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestSQLiteMigrationAndRestartRetainEncryptedHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "historical.sqlite")
	db := awstest.HistoricalSQLite(t, path, "../sqlite/schema", 47, "", nil)
	bucket := versionBucket()
	key := s3.ObjectKey{Bucket: bucket.Key, Name: "historical"}
	ciphertext := []byte{0, 255, 18, 0, 42}
	encryptionKey := []byte{0, 128, 9, 0}
	expires := bucket.Created.Add(time.Hour)
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO s3_buckets (partition,name,account_id,region,created,policy_document,policy_trust,ownership) VALUES (?,?,?,?,?,'',false,'BucketOwnerEnforced')", []any{bucket.Key.Partition, bucket.Key.Name, bucket.AccountID, bucket.Region, bucket.Created}},
		{"INSERT INTO s3_objects (partition,bucket_name,name,modified,size,etag,checksum_algorithm,checksum,content_type,content_encoding,content_language,content_disposition,cache_control,expires) VALUES (?,?,?,?,?,'etag','SHA256','checksum','application/octet-stream','gzip','en','inline','private',?)", []any{bucket.Key.Partition, bucket.Key.Name, key.Name, bucket.Created, 123, expires}},
		{"INSERT INTO s3_object_metadata VALUES (?,?,?,?,?)", []any{bucket.Key.Partition, bucket.Key.Name, key.Name, "custom", "retained"}},
		{"INSERT INTO s3_object_data VALUES (?,?,?,?,?)", []any{bucket.Key.Partition, bucket.Key.Name, key.Name, encryptionKey, ciphertext}},
	} {
		if _, err := db.ExecContext(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var migrated s3.ObjectRecord
	if err := sqls3.New(db).Update(t.Context(), func(tx s3.Transaction) error {
		var err error
		migrated, err = tx.ObjectVersion(s3.ObjectVersionKey{ObjectKey: key, VersionID: "null"})
		if err != nil {
			return err
		}
		stored, err := tx.Bucket(bucket.Key)
		if err != nil || stored.Versioning != "" {
			t.Fatalf("migration enabled versioning: %+v %v", stored, err)
		}
		if stored.ACL == nil {
			t.Fatal("migration lost bucket ownership")
		}
		ownerACL := &s3.AccessControlList{OwnerAccountID: bucket.AccountID, OwnerID: stored.ACL.OwnerID,
			Grants: []s3.ACLGrant{{Type: "CanonicalUser", ID: stored.ACL.OwnerID, Permission: "FULL_CONTROL"}}}
		want := s3.ObjectRecord{Key: key, VersionID: "null", ACL: ownerACL, Sequence: migrated.Sequence, CreatedOrder: migrated.Sequence, Modified: bucket.Created, Size: 123, ETag: "etag", ChecksumAlgorithm: "SHA256", Checksum: "checksum", ChecksumType: "FULL_OBJECT", ContentType: "application/octet-stream", ContentEncoding: "gzip", ContentLanguage: "en", ContentDisposition: "inline", CacheControl: "private", Expires: &expires, Metadata: map[string]string{"custom": "retained"}, EncryptionAlgorithm: "AES256", EncryptionKey: encryptionKey}
		if migrated.Sequence <= 0 || !reflect.DeepEqual(migrated, want) {
			t.Fatalf("migration changed metadata/key: got %+v want %+v", migrated, want)
		}
		data, err := tx.ObjectData(migrated.VersionKey())
		if err != nil || len(data) != 1 || !bytes.Equal(data[0], ciphertext) {
			t.Fatalf("migration changed ciphertext: %x %v", data, err)
		}
		stored.Versioning = "Suspended"
		if err := tx.PutBucket(stored); err != nil {
			return err
		}
		_, err = tx.PutObject(s3.ObjectRecord{Key: key, VersionID: "marker", DeleteMarker: true, Modified: bucket.Created}, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sqls3.New(db).Update(t.Context(), func(tx s3.Transaction) error {
		stored, err := tx.Bucket(bucket.Key)
		if err != nil || stored.Versioning != "Suspended" {
			t.Fatalf("restart lost versioning: %+v %v", stored, err)
		}
		current, err := tx.Object(key)
		if err != nil || !current.DeleteMarker || current.Sequence <= migrated.Sequence {
			t.Fatalf("restart lost marker/order: %+v %v", current, err)
		}
		markerSequence := current.Sequence
		if _, err := tx.DeleteObject(current.VersionKey()); err != nil {
			return err
		}
		current, err = tx.Object(key)
		if err != nil || !reflect.DeepEqual(current, migrated) {
			t.Fatalf("restart/deletion changed historical version: %+v %v", current, err)
		}
		data, err := tx.ObjectData(current.VersionKey())
		if err != nil || len(data) != 1 || !bytes.Equal(data[0], ciphertext) {
			t.Fatalf("restart lost ciphertext: %x %v", data, err)
		}
		if _, err := tx.PutObject(s3.ObjectRecord{Key: key, VersionID: "later", Modified: bucket.Created}, nil); err != nil {
			return err
		}
		current, err = tx.Object(key)
		if err != nil || current.Sequence <= markerSequence {
			t.Fatalf("restart reused sequence: %+v %v", current, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
