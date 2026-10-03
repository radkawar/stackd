package ecr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ecr"
)

func TestRegistryNestedOperationNames(t *testing.T) {
	for _, name := range []string{"team/blobs/uploads/app", "team/manifests/app", "team/blobs/app", "team/tags/list", "team/blobs/uploads/manifests/blobs"} {
		t.Run(name, func(t *testing.T) {
			repository := NewMemoryRepository(nil)
			service := New(Config{Repository: repository, Clock: clock.NewManual(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)), PublicEndpoint: "http://localhost:4566"})
			defer service.Close()
			key := RepositoryKey{Scope: Scope{"aws", "123456789012", "us-east-1"}, Name: name}
			ctx := lifecycleTestContext(key.Scope)
			var password string
			if err := repository.Update(ctx, func(tx Transaction) error {
				if _, err := service.createRepository(tx, &api.CreateRepositoryInput{RepositoryName: str[api.RepositoryName](name)}); err != nil {
					return err
				}
				var err error
				password, _, err = service.issueToken(tx, RepositoryKey{}, "", time.Hour)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			request := func(method, path string, body []byte, want int) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, path, bytes.NewReader(body))
				r.SetBasicAuth("AWS", password)
				if method == http.MethodPut && strings.Contains(path, "/manifests/") && !strings.Contains(path, "?digest=") {
					r.Header.Set("Content-Type", ociManifest)
				}
				if !IsRegistryRequest(r) {
					t.Fatalf("registry route rejected: %s %s", method, path)
				}
				w := httptest.NewRecorder()
				service.RegistryHandler().ServeHTTP(w, r)
				if w.Code != want {
					t.Fatalf("%s %s: status %d, want %d: %s", method, path, w.Code, want, w.Body.String())
				}
				return w
			}
			base := registryPath(key)
			config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
			configDigest := digestBytes(config)
			upload := request(http.MethodPost, base+"/blobs/uploads/", nil, http.StatusAccepted).Header().Get("Location")
			request(http.MethodPut, upload+"?digest="+configDigest, config, http.StatusCreated)
			if got := request(http.MethodGet, base+"/blobs/"+configDigest, nil, http.StatusOK).Body.Bytes(); !bytes.Equal(got, config) {
				t.Fatalf("downloaded config = %s, want %s", got, config)
			}
			manifest, err := json.Marshal(manifestDocument{SchemaVersion: 2, MediaType: ociManifest, Config: &descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: configDigest, Size: int64(len(config))}, Layers: []descriptor{}})
			if err != nil {
				t.Fatal(err)
			}
			request(http.MethodPut, base+"/manifests/latest", manifest, http.StatusCreated)
			if got := request(http.MethodGet, base+"/manifests/latest", nil, http.StatusOK).Body.Bytes(); !bytes.Equal(got, manifest) {
				t.Fatalf("downloaded manifest = %s, want %s", got, manifest)
			}
			var tags struct {
				Name string   `json:"name"`
				Tags []string `json:"tags"`
			}
			if err := json.Unmarshal(request(http.MethodGet, base+"/tags/list", nil, http.StatusOK).Body.Bytes(), &tags); err != nil || tags.Name != strings.TrimPrefix(base, "/v2/") || len(tags.Tags) != 1 || tags.Tags[0] != "latest" {
				t.Fatalf("tag listing = %+v, error %v", tags, err)
			}
		})
	}
}
