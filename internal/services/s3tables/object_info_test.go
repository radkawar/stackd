package s3tables_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awswire"
	owner "stackd/internal/services/s3tables"
)

type metadataOnlyObjects struct {
	owner.WarehouseObjects
	t      *testing.T
	info   owner.ObjectInfo
	onInfo func()
	calls  int
}

func (o *metadataOnlyObjects) Read(context.Context, string, string) ([]byte, error) {
	o.t.Fatal("HEAD fetched object bytes through Read")
	return nil, nil
}
func (o *metadataOnlyObjects) ReadObject(context.Context, string, string) ([]byte, owner.ObjectInfo, error) {
	o.t.Fatal("HEAD fetched object bytes through ReadObject")
	return nil, owner.ObjectInfo{}, nil
}
func (o *metadataOnlyObjects) Info(context.Context, string, string) (owner.ObjectInfo, error) {
	o.calls++
	if o.onInfo != nil {
		o.onInfo()
	}
	return owner.CloneObjectInfo(o.info), nil
}

type metadataReadAuthorizer struct{ denied bool }

func (a *metadataReadAuthorizer) Authorize(_ context.Context, r authorization.Request) *awswire.Error {
	if a.denied && r.Action == "s3tables:GetTableData" {
		return &awswire.Error{Code: "AccessDenied", Message: "read revoked", StatusCode: 403}
	}
	return nil
}

func TestHEADUsesOnlyPersistentMetadata(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "metadata_head")
	location := string(*table.WarehouseLocation) + "/data/large"
	const size int64 = 1<<40 + 123
	modified := time.Date(2026, 11, 4, 1, 2, 3, 0, time.UTC)
	expires := modified.Add(time.Hour)
	objects := &metadataOnlyObjects{WarehouseObjects: f.objects, t: t, info: owner.ObjectInfo{Key: "data/large", Size: size, ETag: "\"retained-etag-3\"", Modified: modified, Attributes: owner.ObjectAttributes{ContentType: "application/parquet", CacheControl: "private", Expires: &expires, Checksums: owner.ObjectChecksums{SHA256: "retained-checksum-3"}}}}
	f.service = owner.New(owner.Config{Repository: f.repository, Objects: objects})
	for _, tc := range []struct {
		name, byteRange, length, contentRange string
		status                                int
	}{
		{"full", "", strconv.FormatInt(size, 10), "", 200},
		{"range", "bytes=1099511627776-", "123", "bytes 1099511627776-1099511627898/1099511627899", 206},
		{"suffix", "bytes=-7", "7", "bytes 1099511627892-1099511627898/1099511627899", 206},
		{"invalid", "bytes=1099511627899-", "", "bytes */1099511627899", 416},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodHead, "/"+strings.TrimPrefix(location, "s3://"), nil).WithContext(f.ctx)
			r.Header.Set("X-Amz-Checksum-Mode", "ENABLED")
			if tc.byteRange != "" {
				r.Header.Set("Range", tc.byteRange)
			}
			w := httptest.NewRecorder()
			if !f.service.HandleData(w, r) || w.Code != tc.status {
				t.Fatalf("HEAD status %d, want %d", w.Code, tc.status)
			}
			if w.Body.Len() != 0 {
				t.Fatal("HEAD emitted a body")
			}
			if w.Header().Get("Content-Range") != tc.contentRange {
				t.Fatalf("Content-Range = %q", w.Header().Get("Content-Range"))
			}
			if tc.status == 416 {
				return
			}
			for key, want := range map[string]string{"Content-Length": tc.length, "ETag": objects.info.ETag, "Content-Type": "application/parquet", "Cache-Control": "private", "Expires": expires.Format(http.TimeFormat), "Last-Modified": modified.Format(http.TimeFormat), "X-Amz-Checksum-Sha256": "retained-checksum-3"} {
				if got := w.Header().Get(key); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
		})
	}
	if objects.calls != 4 {
		t.Fatalf("Info calls = %d", objects.calls)
	}
}

func TestHEADRechecksAuthorizationAfterMetadataRead(t *testing.T) {
	a := &metadataReadAuthorizer{}
	f := newFixture(t, a)
	table := f.create(t, "head_revoke")
	location := string(*table.WarehouseLocation) + "/data/object"
	objects := &metadataOnlyObjects{WarehouseObjects: f.objects, t: t, info: owner.ObjectInfo{Size: 1 << 40}, onInfo: func() { a.denied = true }}
	f.service = owner.New(owner.Config{Repository: f.repository, Objects: objects, Authorizer: a})
	r := httptest.NewRequest(http.MethodHead, "/"+strings.TrimPrefix(location, "s3://"), nil).WithContext(f.ctx)
	w := httptest.NewRecorder()
	if !f.service.HandleData(w, r) || w.Code != http.StatusForbidden {
		t.Fatalf("revoked HEAD returned %d", w.Code)
	}
	if objects.calls != 1 {
		t.Fatalf("Info calls = %d", objects.calls)
	}
	if w.Header().Get("ETag") != "" || w.Header().Get("Content-Length") == strconv.FormatInt(objects.info.Size, 10) {
		t.Fatal("revoked HEAD exposed object metadata")
	}
}
