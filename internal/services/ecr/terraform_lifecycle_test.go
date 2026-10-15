package ecr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	api "stackd/internal/awsapi/ecr"
)

func TestTerraformRepositoryExclusionUpdateAndImageBytes(t *testing.T) {
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository, PublicEndpoint: "http://localhost:4566"})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	key := RepositoryKey{Scope: Scope{"aws", "123456789012", "us-east-1"}, Name: "terraform/image"}
	ctx := lifecycleTestContext(key.Scope)
	name := str[api.RepositoryName](key.Name)
	blob := []byte("independent OCI bytes\x00\xff")
	digest := digestBytes(blob)
	var download string
	if err := repository.Update(ctx, func(tx Transaction) error {
		created, err := service.createRepository(tx, &api.CreateRepositoryInput{RepositoryName: name, ImageTagMutability: str[api.ImageTagMutability]("IMMUTABLE_WITH_EXCLUSION"), ImageTagMutabilityExclusionFilters: api.ImageTagMutabilityExclusionFilters{{FilterType: str[api.ImageTagMutabilityExclusionFilterType]("WILDCARD"), Filter: str[api.ImageTagMutabilityExclusionFilterValue]("dev-*")}}})
		if err != nil {
			return err
		}
		if value(created.Repository.ImageTagMutability) != "IMMUTABLE_WITH_EXCLUSION" {
			t.Fatal("create lost exclusion mode")
		}
		upload, err := service.initiateLayerUpload(tx, &api.InitiateLayerUploadInput{RepositoryName: name})
		if err != nil {
			return err
		}
		if _, err = service.uploadLayerPart(tx, &api.UploadLayerPartInput{RepositoryName: name, UploadId: upload.UploadId, PartFirstByte: new(api.PartSize(0)), PartLastByte: new(api.PartSize(len(blob) - 1)), LayerPartBlob: blob}); err != nil {
			return err
		}
		if _, err = service.completeLayerUpload(tx, &api.CompleteLayerUploadInput{RepositoryName: name, UploadId: upload.UploadId, LayerDigests: api.LayerDigestList{api.LayerDigest(digest)}}); err != nil {
			return err
		}
		manifest, err := json.Marshal(manifestDocument{SchemaVersion: 2, MediaType: ociManifest, Config: &descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digest, Size: int64(len(blob))}, Layers: []descriptor{}})
		if err != nil {
			return err
		}
		if _, err = service.putImage(tx, &api.PutImageInput{RepositoryName: name, ImageManifest: str[api.ImageManifest](string(manifest)), ImageTag: str[api.ImageTag]("dev-first")}); err != nil {
			return err
		}
		if _, err = service.putImageTagMutability(tx, &api.PutImageTagMutabilityInput{RepositoryName: name, RegistryId: str[api.RegistryId](key.AccountID), ImageTagMutability: str[api.ImageTagMutability]("MUTABLE")}); err != nil {
			return err
		}
		read, err := service.describeRepositories(tx, &api.DescribeRepositoriesInput{RepositoryNames: api.RepositoryNameList{api.RepositoryName(key.Name)}})
		if err != nil {
			return err
		}
		if value(read.Repositories[0].ImageTagMutability) != "MUTABLE" || len(read.Repositories[0].ImageTagMutabilityExclusionFilters) != 0 {
			t.Fatal("update retained obsolete exclusions")
		}
		url, err := service.getDownloadURLForLayer(tx, &api.GetDownloadUrlForLayerInput{RepositoryName: name, LayerDigest: str[api.LayerDigest](digest)})
		if err == nil {
			download = value(url.DownloadUrl)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, download, nil)
	response := httptest.NewRecorder()
	service.RegistryHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), blob) {
		t.Fatalf("independent download: %d %q", response.Code, response.Body.Bytes())
	}
	if err := repository.Update(ctx, func(tx Transaction) error {
		_, err := service.deleteRepository(tx, &api.DeleteRepositoryInput{RepositoryName: name, Force: new(api.ForceFlag(true))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTerraformScanningUpdateRequiresRealScanner(t *testing.T) {
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository, PublicEndpoint: "http://localhost:4566"})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	key := RepositoryKey{Scope: Scope{"aws", "123456789012", "us-east-1"}, Name: "terraform/scanning"}
	ctx := lifecycleTestContext(key.Scope)
	if err := repository.Update(ctx, func(tx Transaction) error {
		_, err := service.createRepository(tx, &api.CreateRepositoryInput{RepositoryName: str[api.RepositoryName](key.Name)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := repository.Update(ctx, func(tx Transaction) error {
		_, err := service.putImageScanningConfiguration(tx, &api.PutImageScanningConfigurationInput{
			RepositoryName:             str[api.RepositoryName](key.Name),
			ImageScanningConfiguration: &api.ImageScanningConfiguration{ScanOnPush: new(api.ScanOnPushFlag(true))},
		})
		return err
	})
	if err == nil || wireError(err).Code != "ValidationException" {
		t.Fatalf("scanner-less provider update = %v", err)
	}
	err = repository.Update(ctx, func(tx Transaction) error {
		_, err := service.putRegistryScanningConfiguration(tx, &api.PutRegistryScanningConfigurationInput{
			ScanType: str[api.ScanType]("BASIC"),
			Rules: api.RegistryScanningRuleList{{
				ScanFrequency: str[api.ScanFrequency]("SCAN_ON_PUSH"),
				RepositoryFilters: api.ScanningRepositoryFilterList{{
					FilterType: str[api.ScanningRepositoryFilterType]("WILDCARD"),
					Filter:     str[api.ScanningRepositoryFilterValue]("*"),
				}},
			}},
		})
		return err
	})
	if err == nil || wireError(err).Code != "ValidationException" {
		t.Fatalf("scanner-less registry update = %v", err)
	}
	if err := repository.View(ctx, func(r Reader) error {
		repo, err := r.Repository(key)
		if err == nil && repo.ScanOnPush {
			t.Fatal("rejected update retained metadata-only scan success")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
