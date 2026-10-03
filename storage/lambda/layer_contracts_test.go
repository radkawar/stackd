package lambda_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"stackd/storage/lambda"
)

func TestLayerVersionsAreImmutableDetachedAndScoped(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		key := lambda.LayerKey{Scope: deployment().Key.Scope, Name: "layer"}
		original := lambda.LayerVersionRecord{
			Key: lambda.LayerVersionKey{LayerKey: key, Version: 1}, CodeSHA256: "layer-hash", CodeSize: 3,
			Reference:   &lambda.S3ObjectReference{Bucket: "bucket", Key: "layer.zip", VersionID: "object-version"},
			Description: "original", LicenseInfo: "MIT", Created: deployment().Modified,
			CompatibleRuntimes: []string{"python3.12"}, CompatibleArchitectures: []string{"x86_64"},
		}
		policy := lambda.LayerPolicy{Key: original.Key, Document: `{"Statement":[]}`, Revision: "revision", PrincipalIDs: map[string]string{"reader": "principal-id"}}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			version, err := tx.AllocateLayerVersion(key)
			if err != nil || version != 1 {
				t.Fatalf("initial version = %d, %v", version, err)
			}
			if err := tx.PutLayerVersion(original); err != nil {
				return err
			}
			if err := tx.PutLayerPolicy(policy); err != nil {
				return err
			}
			original.CompatibleRuntimes[0] = "caller mutation"
			original.CompatibleArchitectures[0] = "caller mutation"
			original.Reference.VersionID = "caller mutation"
			policy.PrincipalIDs["reader"] = "caller mutation"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				one, err := r.LayerVersion(original.Key)
				if err != nil {
					return err
				}
				versions, err := r.LayerVersions(key)
				if err != nil {
					return err
				}
				layers, err := r.Layers(key.Scope)
				if err != nil {
					return err
				}
				if len(versions) != 1 || len(layers) != 1 {
					t.Fatalf("catalog = %#v; versions = %#v", layers, versions)
				}
				for _, got := range []lambda.LayerVersionRecord{one, versions[0], layers[0]} {
					if got.Description != "original" || got.LicenseInfo != "MIT" || got.CodeSHA256 != "layer-hash" || got.CodeSize != 3 || !got.Created.Equal(original.Created) || !reflect.DeepEqual(got.CompatibleRuntimes, []string{"python3.12"}) || !reflect.DeepEqual(got.CompatibleArchitectures, []string{"x86_64"}) || got.Reference == nil || *got.Reference != (lambda.S3ObjectReference{Bucket: "bucket", Key: "layer.zip", VersionID: "object-version"}) {
						t.Fatalf("stored layer changed through caller or reader: %#v", got)
					}
				}
				// Mutate after comparing all paths: each next read must be detached.
				for _, got := range []lambda.LayerVersionRecord{one, versions[0], layers[0]} {
					got.CompatibleRuntimes[0] = "reader mutation"
					got.CompatibleArchitectures[0] = "reader mutation"
					got.Reference.Key = "reader mutation"
				}
				got, err := r.LayerPolicy(original.Key)
				if err != nil {
					return err
				}
				if got.Document != policy.Document || got.Revision != policy.Revision || got.PrincipalIDs["reader"] != "principal-id" {
					t.Fatalf("policy changed through caller or reader: %#v", got)
				}
				got.PrincipalIDs["reader"] = "reader mutation"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			replacement := original
			replacement.Description = "overwrite"
			return tx.PutLayerVersion(replacement)
		}); err == nil {
			t.Fatal("published layer version was overwritten")
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			got, err := r.LayerVersion(original.Key)
			if err == nil && got.Description != "original" {
				t.Fatal("rejected overwrite changed immutable metadata")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		abort := errors.New("abort catalog update")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if _, err := tx.AllocateLayerVersion(key); err != nil {
				return err
			}
			if err := tx.DeleteLayerVersion(original.Key); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if _, err := tx.LayerPolicy(original.Key); err != nil {
				t.Fatalf("rollback lost policy: %v", err)
			}
			for range 2 {
				if err := tx.DeleteLayerVersion(original.Key); err != nil {
					return err
				}
			}
			if _, err := tx.LayerPolicy(original.Key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("deleted layer retained policy: %v", err)
			}
			if _, err := tx.LayerVersion(original.Key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("deleted layer remains visible: %v", err)
			}
			versions, err := tx.LayerVersions(key)
			if err != nil || len(versions) != 0 {
				t.Fatalf("deleted catalog = %#v, %v", versions, err)
			}
			next, err := tx.AllocateLayerVersion(key)
			if err != nil || next != 2 {
				t.Fatalf("deletion reset allocation or rollback consumed a version: %d, %v", next, err)
			}
			other := key
			other.Account = "222222222222"
			next, err = tx.AllocateLayerVersion(other)
			if err != nil || next != 1 {
				t.Fatalf("layer counters crossed scope: %d, %v", next, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLayerCatalogLatestExtantOrderingAndMetadataPresence(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		scope := deployment().Key.Scope
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			for _, name := range []string{"z", "a"} {
				key := lambda.LayerKey{Scope: scope, Name: name}
				for range 3 {
					version, err := tx.AllocateLayerVersion(key)
					if err != nil {
						return err
					}
					record := lambda.LayerVersionRecord{Key: lambda.LayerVersionKey{LayerKey: key, Version: version}, CodeSHA256: "archive"}
					if version == 2 {
						record.CompatibleRuntimes, record.CompatibleArchitectures = []string{}, []string{}
					}
					if err := tx.PutLayerVersion(record); err != nil {
						return err
					}
				}
			}
			return tx.DeleteLayerVersion(lambda.LayerVersionKey{LayerKey: lambda.LayerKey{Scope: scope, Name: "a"}, Version: 3})
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			layers, err := r.Layers(scope)
			if err != nil || len(layers) != 2 || layers[0].Key.Name != "a" || layers[0].Key.Version != 2 || layers[1].Key.Name != "z" || layers[1].Key.Version != 3 {
				t.Fatalf("latest extant catalog order = %#v, %v", layers, err)
			}
			versions, err := r.LayerVersions(lambda.LayerKey{Scope: scope, Name: "z"})
			if err != nil || len(versions) != 3 || versions[0].Key.Version != 3 || versions[1].Key.Version != 2 || versions[2].Key.Version != 1 {
				t.Fatalf("version order = %#v, %v", versions, err)
			}
			if versions[0].CompatibleRuntimes != nil || versions[0].CompatibleArchitectures != nil || versions[1].CompatibleRuntimes == nil || versions[1].CompatibleArchitectures == nil || len(versions[1].CompatibleRuntimes) != 0 || len(versions[1].CompatibleArchitectures) != 0 {
				t.Fatal("catalog collapsed omitted and explicitly empty metadata")
			}
			other := scope
			other.Region = "us-west-2"
			layers, err = r.Layers(other)
			if err != nil || len(layers) != 0 {
				t.Fatalf("catalog crossed region: %#v, %v", layers, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLayerArchivesFollowCatalogAndDetachedFunctionSnapshots(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		latest := deployment()
		layerScope := latest.Key.Scope
		layerScope.Account = "222222222222"
		key := lambda.LayerVersionKey{LayerKey: lambda.LayerKey{Scope: layerScope, Name: "shared"}, Version: 1}
		owner := lambda.LayerVersionOwner{StackID: "stack-a", LogicalID: "Layer", Token: "request-a"}
		archive := lambda.CodeArchiveKey{Scope: layerScope, SHA256: "layer-archive"}
		until := latest.Modified.Add(time.Minute)
		latest.Layers = []lambda.LayerAttachment{{Key: key, CodeSHA256: archive.SHA256, CodeSize: 9}}
		latest.Reference = &lambda.S3ObjectReference{Bucket: "code", Key: "function.zip", VersionID: "version"}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutCodeArchive(lambda.CodeArchive{Key: archive, Code: []byte("layer ZIP"), CreatedAt: latest.Modified, RetainUntil: until}); err != nil {
				return err
			}
			return tx.PutLayerVersion(lambda.LayerVersionRecord{Key: key, Owner: owner, CodeSHA256: archive.SHA256, CodeSize: 9})
		}); err != nil {
			t.Fatal(err)
		}
		collect := func(want int64) {
			t.Helper()
			if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
				got, err := tx.DeleteExpiredCodeArchives(until.Add(time.Second))
				if err != nil || got != want {
					t.Fatalf("collected %d archives, want %d: %v", got, want, err)
				}
				stored, err := tx.CodeArchive(archive)
				if want == 0 && (err != nil || string(stored.Code) != "layer ZIP") {
					t.Fatalf("reachable layer bytes lost: %q, %v", stored.Code, err)
				}
				if want == 1 && !errors.Is(err, lambda.ErrNotFound) {
					t.Fatalf("unreferenced bytes retained after expiration: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		collect(0) // Catalog alone retains bytes, even after signed URLs expire.
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
			latest.Layers[0].CodeSHA256 = "caller mutation"
			latest.Reference.VersionID = "caller mutation"
			return tx.DeleteLayerVersion(key)
		}); err != nil {
			t.Fatal(err)
		}
		collect(0) // Latest retains the deleted layer in the publisher's scope.
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			if _, err := r.OwnedLayerVersion(key.LayerKey, owner); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("deleted catalog retained ownership while attachments survived: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			stored, err := tx.Function(latest.Key)
			if err != nil {
				return err
			}
			if len(stored.Layers) != 1 || stored.Layers[0].CodeSHA256 != archive.SHA256 || stored.Layers[0].Key != key || stored.Reference == nil || stored.Reference.VersionID != "version" {
				t.Fatalf("caller changed function attachment snapshot: %#v", stored)
			}
			stored.Version, err = tx.AllocateFunctionVersion(stored.Key)
			if err != nil {
				return err
			}
			if err := tx.PutFunctionVersion(stored); err != nil {
				return err
			}
			stored.Layers[0].CodeSHA256 = "reader mutation"
			stored.Reference.Key = "reader mutation"
			latest.Layers, latest.Reference = nil, nil
			return tx.PutFunction(latest)
		}); err != nil {
			t.Fatal(err)
		}
		collect(0) // Published alone retains bytes after latest is cleared.
		for range 2 {
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				stored, err := r.FunctionVersion(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 1})
				if err != nil {
					return err
				}
				if len(stored.Layers) != 1 || stored.Layers[0].CodeSHA256 != archive.SHA256 || stored.Reference == nil || stored.Reference.Key != "function.zip" {
					t.Fatalf("published attachment snapshot mutated: %#v", stored)
				}
				stored.Layers[0].CodeSHA256 = "reader mutation"
				stored.Reference.Key = "reader mutation"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			return tx.DeleteFunctionVersion(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 1})
		}); err != nil {
			t.Fatal(err)
		}
		collect(1)
	})
}

func TestLayerQuotaExcludesReferencesAndDeletedAttachedVersions(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		function := deployment()
		scope := function.Key.Scope
		scope.Account = "222222222222"
		copyKey := lambda.LayerVersionKey{LayerKey: lambda.LayerKey{Scope: scope, Name: "copy"}, Version: 1}
		referenceKey := lambda.LayerVersionKey{LayerKey: lambda.LayerKey{Scope: scope, Name: "reference"}, Version: 1}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutLayerVersion(lambda.LayerVersionRecord{Key: copyKey, CodeSHA256: "copy", CodeSize: 11}); err != nil {
				return err
			}
			if err := tx.PutLayerVersion(lambda.LayerVersionRecord{Key: referenceKey, CodeSHA256: "reference", CodeSize: 23, Reference: &lambda.S3ObjectReference{Bucket: "source", Key: "layer.zip"}}); err != nil {
				return err
			}
			function.Layers = []lambda.LayerAttachment{{Key: copyKey, CodeSHA256: "copy", CodeSize: 11}, {Key: referenceKey, CodeSHA256: "reference", CodeSize: 23}}
			return tx.PutFunction(function)
		}); err != nil {
			t.Fatal(err)
		}
		usage := func(want int64) {
			t.Helper()
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				got, err := r.AccountUsage(scope)
				if err != nil {
					return err
				}
				if got.TotalCodeSize != want {
					t.Fatalf("managed layer storage = %d, want %d", got.TotalCodeSize, want)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		usage(11)
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.DeleteLayerVersion(copyKey) }); err != nil {
			t.Fatal(err)
		}
		usage(0)
	})
}
