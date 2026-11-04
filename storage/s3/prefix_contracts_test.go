package s3_test

import (
	"cmp"
	"reflect"
	"slices"
	"strings"
	"testing"

	"stackd/storage/s3"
)

func TestUTF8PrefixRangesPreserveAllListingCursors(t *testing.T) {
	forVersionRepositories(t, func(t *testing.T, repository s3.Repository) {
		bucket := versionBucket()
		names := []string{"A", "a", "a/", "a/\x00x", "a/deleted", "a/é", "a/😀", "a/\U0010ffff", "a/\U0010ffffx", "b", "e\u0301/key", "é/key", "é/\U0010ffff", "中/key", "😀/key"}
		slices.Sort(names)
		var versions []s3.ObjectRecord
		var uploads []s3.MultipartUploadRecord
		if err := repository.Update(t.Context(), func(tx s3.Transaction) error {
			if err := tx.PutBucket(bucket); err != nil {
				return err
			}
			for _, name := range names {
				key := s3.ObjectKey{Bucket: bucket.Key, Name: name}
				for _, id := range []string{"one", "two"} {
					sequence, err := tx.PutObject(s3.ObjectRecord{Key: key, VersionID: id, Modified: bucket.Created}, []byte(id))
					if err != nil {
						return err
					}
					versions = append(versions, s3.ObjectRecord{Key: key, VersionID: id, Sequence: sequence})
					upload := s3.MultipartUploadRecord{ObjectRecord: s3.ObjectRecord{Key: key, Modified: bucket.Created}}
					if err := tx.PutMultipartUpload(&upload); err != nil {
						return err
					}
					uploads = append(uploads, upload)
				}
				if name == "a/deleted" {
					sequence, err := tx.PutObject(s3.ObjectRecord{Key: key, VersionID: "marker", DeleteMarker: true, Modified: bucket.Created}, nil)
					if err != nil {
						return err
					}
					versions = append(versions, s3.ObjectRecord{Key: key, VersionID: "marker", Sequence: sequence})
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		slices.SortFunc(versions, func(a, b s3.ObjectRecord) int {
			if order := strings.Compare(a.Key.Name, b.Key.Name); order != 0 {
				return order
			}
			return cmp.Compare(b.Sequence, a.Sequence)
		})
		if err := repository.View(t.Context(), func(tx s3.Reader) error {
			for _, prefix := range []string{"", "a", "a/", "a/\x00", "a/\U0010ffff", "é/", "e\u0301/", "中/", "😀/", "absent/"} {
				for _, after := range []string{"", "a/é", "zzzz", "\U0010ffff"} {
					want := []string{}
					for _, name := range names {
						if strings.HasPrefix(name, prefix) && name > after && name != "a/deleted" {
							want = append(want, name)
						}
					}
					got := []string{}
					query := s3.ObjectQuery{Bucket: bucket.Key, Prefix: prefix, After: after, Limit: 2}
					for range len(names) + 1 {
						rows, err := tx.Objects(query)
						if err != nil {
							return err
						}
						if len(rows) == 0 {
							break
						}
						for _, row := range rows {
							if row.VersionID != "two" || row.DeleteMarker {
								t.Errorf("current version prefix=%q: %+v", prefix, row)
							}
							got = append(got, row.Key.Name)
						}
						query.After = rows[len(rows)-1].Key.Name
					}
					if !reflect.DeepEqual(got, want) {
						t.Errorf("current prefix=%q after=%q: got=%q want=%q", prefix, after, got, want)
					}
				}
				wantVersions := []string{}
				for _, row := range versions {
					if strings.HasPrefix(row.Key.Name, prefix) {
						wantVersions = append(wantVersions, row.Key.Name+":"+row.VersionID)
					}
				}
				for _, useOrder := range []bool{false, true} {
					got := []string{}
					query := s3.VersionQuery{Bucket: bucket.Key, Prefix: prefix, Limit: 1}
					for range len(versions) + 1 {
						rows, err := tx.ObjectVersions(query)
						if err != nil {
							return err
						}
						if len(rows) == 0 {
							break
						}
						last := rows[len(rows)-1]
						got = append(got, last.Key.Name+":"+last.VersionID)
						query.AfterKey, query.AfterVersion = last.Key.Name, last.VersionID
						if useOrder {
							query.AfterOrder = &last.CreatedOrder
							query.AfterVersion = ""
						}
					}
					if !reflect.DeepEqual(got, wantVersions) {
						t.Errorf("versions prefix=%q explicit-order=%t: got=%q want=%q", prefix, useOrder, got, wantVersions)
					}
				}
				wantUploads := []string{}
				for _, row := range uploads {
					if strings.HasPrefix(row.Key.Name, prefix) {
						wantUploads = append(wantUploads, row.Key.Name+":"+row.UploadID)
					}
				}
				got := []string{}
				query := s3.MultipartQuery{Bucket: bucket.Key, Prefix: prefix, Limit: 1}
				for range len(uploads) + 1 {
					rows, err := tx.MultipartUploads(query)
					if err != nil {
						return err
					}
					if len(rows) == 0 {
						break
					}
					last := rows[len(rows)-1]
					got = append(got, last.Key.Name+":"+last.UploadID)
					query.AfterKey, query.AfterOrder = last.Key.Name, &last.CreatedOrder
				}
				if !reflect.DeepEqual(got, wantUploads) {
					t.Errorf("uploads prefix=%q: got=%q want=%q", prefix, got, wantUploads)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
