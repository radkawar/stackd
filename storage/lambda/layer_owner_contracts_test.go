package lambda_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awstest"
	"stackd/internal/awswire"
	service "stackd/internal/services/lambda"
	"stackd/journal"
	"stackd/storage/lambda"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqljournal "stackd/storage/sqlite/journal"
	sqllambda "stackd/storage/sqlite/lambda"
)

func layerOwnerZIP(t *testing.T, body string) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("nodejs/node_modules/owned/index.js")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

type layerOwnerSource struct {
	read func(context.Context) ([]byte, *awswire.Error)
}

func (s layerOwnerSource) ReadCode(ctx context.Context, _ lambda.Scope, _ string, ref lambda.S3ObjectReference, _ bool) ([]byte, lambda.S3ObjectReference, *awswire.Error) {
	code, wire := s.read(ctx)
	ref.VersionID = "resolved-object-version"
	return code, ref, wire
}

func (s layerOwnerSource) ReadReference(ctx context.Context, _ lambda.Scope, _ string, _ lambda.S3ObjectReference) ([]byte, *awswire.Error) {
	return s.read(ctx)
}

func layerOwnerPublication(t *testing.T, s *service.Service, ctx context.Context, in *api.PublishLayerVersionInput) *api.PublishLayerVersionOutput {
	t.Helper()
	out, wire := storedAliasCommand(t, s, ctx, "PublishLayerVersion", in)
	if wire != nil {
		t.Fatal(wire)
	}
	return out.(*api.PublishLayerVersionOutput)
}

func sameLayerPublication(t *testing.T, got, want *api.PublishLayerVersionOutput) {
	t.Helper()
	// Signed download URLs are renewable; the publication and code identity are not.
	actual, expected := *got, *want
	actualContent, expectedContent := *got.Content, *want.Content
	actualContent.Location, expectedContent.Location = nil, nil
	actual.Content, expected.Content = &actualContent, &expectedContent
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("recovery changed immutable publication: %+v; want %+v", actual, expected)
	}
}

func TestLayerOwnerScopedImmutableAndTransactional(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		base := lambda.LayerKey{Scope: deployment().Key.Scope, Name: "owned-layer"}
		owner := lambda.LayerVersionOwner{StackID: "stack-a", LogicalID: "Layer", Token: "request-a"}
		keys := []lambda.LayerKey{base, base, base, base, base}
		keys[1].Region, keys[2].Account, keys[3].Partition, keys[4].Name = "us-west-2", "222222222222", "aws-cn", "another-layer"
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			for _, key := range keys {
				for range 2 {
					version, err := tx.AllocateLayerVersion(key)
					if err != nil {
						return err
					}
					v := lambda.LayerVersionRecord{Key: lambda.LayerVersionKey{LayerKey: key, Version: version}, CodeSHA256: key.ARN(), CodeSize: 9, Created: deployment().Modified, CompatibleRuntimes: []string{"nodejs22.x"}, CompatibleArchitectures: []string{"arm64"}, Reference: &lambda.S3ObjectReference{Bucket: "source", Key: "layer.zip", VersionID: "exact-source"}, SigningProfileVersionARN: "signing-profile", SigningJobARN: "signing-job"}
					if version == 1 {
						v.Owner = owner
					}
					if err := tx.PutLayerVersion(v); err != nil {
						return err
					}
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		check := func() {
			t.Helper()
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				for _, key := range keys {
					for range 2 {
						got, err := r.OwnedLayerVersion(key, owner)
						if err != nil || got.Key.LayerKey != key || got.Key.Version != 1 || got.CodeSHA256 != key.ARN() || got.CompatibleRuntimes[0] != "nodejs22.x" || got.CompatibleArchitectures[0] != "arm64" || got.Reference.VersionID != "exact-source" || got.SigningJobARN != "signing-job" || got.SigningProfileVersionARN != "signing-profile" {
							t.Fatalf("scoped immutable receipt = %+v %v", got, err)
						}
						got.CompatibleRuntimes[0], got.CompatibleArchitectures[0], got.Reference.VersionID = "mutated", "mutated", "mutated"
					}
					for _, wrong := range []lambda.LayerVersionOwner{{}, {StackID: owner.StackID, LogicalID: owner.LogicalID}, {StackID: "other-stack", LogicalID: owner.LogicalID, Token: owner.Token}, {StackID: owner.StackID, LogicalID: "Other", Token: owner.Token}, {StackID: owner.StackID, LogicalID: owner.LogicalID, Token: "other-token"}} {
						if _, err := r.OwnedLayerVersion(key, wrong); !errors.Is(err, lambda.ErrNotFound) {
							t.Fatalf("lookup adopted native/foreign publication: %+v %v", wrong, err)
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		check()
		for _, invalid := range []lambda.LayerVersionOwner{owner, {StackID: owner.StackID, LogicalID: owner.LogicalID}} {
			if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
				version, err := tx.AllocateLayerVersion(base)
				if err != nil {
					return err
				}
				return tx.PutLayerVersion(lambda.LayerVersionRecord{Key: lambda.LayerVersionKey{LayerKey: base, Version: version}, Owner: invalid, Created: deployment().Modified})
			}); err == nil {
				t.Fatalf("accepted duplicate or incomplete owner: %+v", invalid)
			}
		}
		abort := errors.New("abort deletion")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.DeleteLayerVersion(lambda.LayerVersionKey{LayerKey: base, Version: 1}); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatal(err)
		}
		check()
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			for _, version := range []uint64{1, 2} {
				if err := tx.DeleteLayerVersion(lambda.LayerVersionKey{LayerKey: base, Version: version}); err != nil {
					return err
				}
			}
			if _, err := tx.OwnedLayerVersion(base, owner); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("deletion retained receipt: %v", err)
			}
			version, err := tx.AllocateLayerVersion(base)
			if err != nil || version != 3 {
				t.Fatalf("rollback or name reuse changed allocation: %d %v", version, err)
			}
			return tx.PutLayerVersion(lambda.LayerVersionRecord{Key: lambda.LayerVersionKey{LayerKey: base, Version: version}, Owner: owner, CodeSHA256: "replacement", Created: deployment().Modified})
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			got, err := r.OwnedLayerVersion(base, owner)
			if err != nil || got.Key.Version != 3 || got.CodeSHA256 != "replacement" {
				t.Fatalf("name reuse recovered stale receipt: %+v %v", got, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLayerOwnerRecoverySkipsChangedAndDeletedSource(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		key := lambda.LayerKey{Scope: deployment().Key.Scope, Name: "recover-layer"}
		ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
		owner := lambda.LayerVersionOwner{StackID: "stack-a", LogicalID: "Layer", Token: "request-a"}
		owned := service.WithLayerVersionOwner(ctx, owner)
		original := layerOwnerZIP(t, "exports.value = 'original';")
		current := original
		var missing bool
		var reads atomic.Int32
		source := layerOwnerSource{read: func(context.Context) ([]byte, *awswire.Error) {
			reads.Add(1)
			if missing {
				return nil, &awswire.Error{Code: "NoSuchKey", Message: "source deleted", StatusCode: 404}
			}
			return current, nil
		}}
		s := service.New(service.Config{Repository: repo, CodeSource: source, PublicEndpoint: "http://localhost"})
		t.Cleanup(func() { _ = s.Close() })
		in := &api.PublishLayerVersionInput{LayerName: new(api.LayerName(key.Name)), Content: &api.LayerVersionContentInput{S3Bucket: new(api.S3Bucket("source")), S3Key: new(api.S3Key("layer.zip"))}, Description: new(api.Description("immutable")), LicenseInfo: new(api.LicenseInfo("MIT")), CompatibleRuntimes: []api.Runtime{api.Runtime("nodejs22.x")}, CompatibleArchitectures: []api.Architecture{api.Architecture("arm64")}}
		first := layerOwnerPublication(t, s, owned, in)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = service.New(service.Config{Repository: repo, CodeSource: source, PublicEndpoint: "http://localhost"})
		current = layerOwnerZIP(t, "exports.value = 'changed';")
		in.Description, in.LicenseInfo = new(api.Description("changed request")), new(api.LicenseInfo("changed license"))
		for _, deleted := range []bool{false, true} {
			missing = deleted
			sameLayerPublication(t, layerOwnerPublication(t, s, owned, in), first)
			if reads.Load() != 1 {
				t.Fatalf("receipt recovery reloaded source: %d reads", reads.Load())
			}
		}
		if err := repo.View(ctx, func(r lambda.Reader) error {
			v, err := r.OwnedLayerVersion(key, owner)
			if err != nil || v.Key.Version != 1 || v.Description != "immutable" || v.LicenseInfo != "MIT" {
				t.Fatalf("recovery changed receipt: %+v %v", v, err)
			}
			archive, err := r.CodeArchive(lambda.CodeArchiveKey{Scope: key.Scope, SHA256: v.CodeSHA256})
			if err != nil || !bytes.Equal(archive.Code, original) {
				t.Fatalf("recovery replaced downloaded bytes: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		missing, current = false, original
		for _, want := range []api.LayerVersionNumber{2, 3} {
			got := layerOwnerPublication(t, s, ctx, in)
			if *got.Version != want || *got.Content.CodeSha256 != *first.Content.CodeSha256 {
				t.Fatalf("native identical publication reused version: %+v", got)
			}
		}
		for _, target := range []api.LayerVersionNumber{1, 2, 3} {
			bad := owner
			bad.Token = "foreign"
			if target != 1 {
				bad = owner
			}
			_, wire := storedAliasCommand(t, s, service.WithLayerVersionOwner(ctx, bad), "DeleteLayerVersion", &api.DeleteLayerVersionInput{LayerName: in.LayerName, VersionNumber: new(target)})
			if wire == nil || wire.Code != "AccessDeniedException" {
				t.Fatalf("owned delete accepted foreign/native version %d: %v", target, wire)
			}
		}
		for _, invalid := range []lambda.LayerVersionOwner{{}, {StackID: owner.StackID, LogicalID: owner.LogicalID}, {StackID: owner.StackID, Token: owner.Token}, {LogicalID: owner.LogicalID, Token: owner.Token}} {
			for _, operation := range []struct {
				name string
				in   any
			}{{"PublishLayerVersion", in}, {"DeleteLayerVersion", &api.DeleteLayerVersionInput{LayerName: in.LayerName, VersionNumber: new(api.LayerVersionNumber(1))}}} {
				_, wire := storedAliasCommand(t, s, service.WithLayerVersionOwner(ctx, invalid), operation.name, operation.in)
				if wire == nil || wire.Code != "AccessDeniedException" {
					t.Fatalf("incomplete owner accepted %s: %v", operation.name, wire)
				}
			}
		}
		for range 2 {
			if _, wire := storedAliasCommand(t, s, owned, "DeleteLayerVersion", &api.DeleteLayerVersionInput{LayerName: in.LayerName, VersionNumber: new(api.LayerVersionNumber(1))}); wire != nil {
				t.Fatal(wire)
			}
		}
		if err := repo.View(ctx, func(r lambda.Reader) error {
			if _, err := r.OwnedLayerVersion(key, owner); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("delete retained receipt: %v", err)
			}
			for _, version := range []uint64{2, 3} {
				if _, err := r.LayerVersion(lambda.LayerVersionKey{LayerKey: key, Version: version}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if got := layerOwnerPublication(t, s, owned, in); *got.Version != 4 {
			t.Fatalf("owned recreation reused deleted generation: %d", *got.Version)
		}
	})
}

func TestLayerOwnerConcurrentPublicationRecoversCommittedArtifact(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		key := lambda.LayerKey{Scope: deployment().Key.Scope, Name: "concurrent-layer"}
		ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
		owner := lambda.LayerVersionOwner{StackID: "stack-a", LogicalID: "Layer", Token: "request-a"}
		owned := service.WithLayerVersionOwner(ctx, owner)
		archives := [][]byte{layerOwnerZIP(t, "exports.value = 'first';"), layerOwnerZIP(t, "exports.value = 'second';")}
		entered, release := make(chan int, 2), make(chan struct{})
		var calls atomic.Int32
		source := layerOwnerSource{read: func(ctx context.Context) ([]byte, *awswire.Error) {
			index := int(calls.Add(1)) - 1
			entered <- index
			select {
			case <-release:
				return archives[index], nil
			case <-ctx.Done():
				return nil, &awswire.Error{Code: "ServiceException", Message: ctx.Err().Error(), StatusCode: 500}
			}
		}}
		s := service.New(service.Config{Repository: repo, CodeSource: source, PublicEndpoint: "http://localhost"})
		t.Cleanup(func() { _ = s.Close() })
		in := &api.PublishLayerVersionInput{LayerName: new(api.LayerName(key.Name)), Content: &api.LayerVersionContentInput{S3Bucket: new(api.S3Bucket("source")), S3Key: new(api.S3Key("layer.zip"))}}
		type result struct {
			out  any
			wire *awswire.Error
		}
		results := make(chan result, 2)
		for range 2 {
			go func() {
				out, wire := storedAliasCommand(t, s, owned, "PublishLayerVersion", in)
				results <- result{out, wire}
			}()
		}
		for range 2 {
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		close(release)
		first, second := <-results, <-results
		if first.wire != nil || second.wire != nil {
			t.Fatalf("parallel publication failed: %v %v", first.wire, second.wire)
		}
		sameLayerPublication(t, first.out.(*api.PublishLayerVersionOutput), second.out.(*api.PublishLayerVersionOutput))
		if err := repo.View(ctx, func(r lambda.Reader) error {
			v, err := r.OwnedLayerVersion(key, owner)
			if err != nil || v.Key.Version != 1 {
				t.Fatalf("parallel publication duplicated receipt: %+v %v", v, err)
			}
			archive, err := r.CodeArchive(lambda.CodeArchiveKey{Scope: key.Scope, SHA256: v.CodeSHA256})
			if err != nil || (!bytes.Equal(archive.Code, archives[0]) && !bytes.Equal(archive.Code, archives[1])) {
				t.Fatalf("parallel recovery lost downloaded artifact: %v", err)
			}
			for _, code := range archives {
				digest := sha256.Sum256(code)
				hash := base64.StdEncoding.EncodeToString(digest[:])
				if hash != v.CodeSHA256 {
					if _, err := r.CodeArchive(lambda.CodeArchiveKey{Scope: key.Scope, SHA256: hash}); !errors.Is(err, lambda.ErrNotFound) {
						t.Fatalf("losing recovery committed an unused archive: %v", err)
					}
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		native := &api.PublishLayerVersionInput{LayerName: in.LayerName, Content: &api.LayerVersionContentInput{ZipFile: archives[0]}}
		if got := layerOwnerPublication(t, s, ctx, native); *got.Version != 2 {
			t.Fatalf("concurrent recovery consumed allocation: %d", *got.Version)
		}
	})
}

func TestSQLiteLayerOwnerReopenAndLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := lambda.LayerKey{Scope: deployment().Key.Scope, Name: "persistent-layer"}
	ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
	owner := lambda.LayerVersionOwner{StackID: "stack-a", LogicalID: "Layer", Token: "request-a"}
	owned := service.WithLayerVersionOwner(ctx, owner)
	code := layerOwnerZIP(t, "exports.value = 'persistent';")
	s := service.New(service.Config{Repository: sqllambda.New(db), PublicEndpoint: "http://localhost", CodeSource: layerOwnerSource{read: func(context.Context) ([]byte, *awswire.Error) { return code, nil }}})
	in := &api.PublishLayerVersionInput{LayerName: new(api.LayerName(key.Name)), Content: &api.LayerVersionContentInput{S3Bucket: new(api.S3Bucket("source")), S3Key: new(api.S3Key("layer.zip"))}, Description: new(api.Description("persistent description"))}
	first := layerOwnerPublication(t, s, owned, in)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	// No CodeSource exists after restart: successful recovery must use retained bytes.
	s = service.New(service.Config{Repository: sqllambda.New(db), PublicEndpoint: "http://localhost"})
	t.Cleanup(func() { _ = s.Close() })
	sameLayerPublication(t, layerOwnerPublication(t, s, owned, in), first)
	legacyPath := filepath.Join(t.TempDir(), "legacy.sqlite")
	historical := awstest.HistoricalSQLite(t, legacyPath, "../sqlite/schema", 299, path, nil)
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	legacyDB, err := sqlite.Open(t.Context(), legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacyDB.Close() })
	repo := sqllambda.New(legacyDB)
	if err := repo.View(ctx, func(r lambda.Reader) error {
		if _, err := r.OwnedLayerVersion(key, owner); !errors.Is(err, lambda.ErrNotFound) {
			t.Fatalf("migration invented receipt: %v", err)
		}
		v, err := r.LayerVersion(lambda.LayerVersionKey{LayerKey: key, Version: 1})
		if err != nil || v.Owner != (lambda.LayerVersionOwner{}) || v.CodeSHA256 != string(*first.Content.CodeSha256) || v.Description != "persistent description" {
			t.Fatalf("migration changed legacy publication: %+v %v", v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	legacy := service.New(service.Config{Repository: repo, PublicEndpoint: "http://localhost"})
	t.Cleanup(func() { _ = legacy.Close() })
	_, wire := storedAliasCommand(t, legacy, owned, "DeleteLayerVersion", &api.DeleteLayerVersionInput{LayerName: in.LayerName, VersionNumber: first.Version})
	if wire == nil || wire.Code != "AccessDeniedException" {
		t.Fatalf("owner adopted migrated legacy publication: %v", wire)
	}
	in.Content = &api.LayerVersionContentInput{ZipFile: code}
	if got := layerOwnerPublication(t, legacy, owned, in); *got.Version != 2 {
		t.Fatalf("owner adopted legacy publication instead of allocating: %d", *got.Version)
	}
}

func TestLayerOwnerPublicationAndDeletionJournalRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repo lambda.Repository
			var events journal.Storage
			if backend == "memory" {
				domain := memory.NewDomain()
				repo, events = lambda.NewMemory(domain), journal.NewMemory(domain)
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "events.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo, events = sqllambda.New(db), sqljournal.New(db)
			}
			key := lambda.LayerKey{Scope: deployment().Key.Scope, Name: "atomic-layer"}
			ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
			owner := lambda.LayerVersionOwner{StackID: "private-stack-identity", LogicalID: "private-logical-identity", Token: "private-receipt-token"}
			owned := service.WithLayerVersionOwner(ctx, owner)
			code := layerOwnerZIP(t, "exports.value = 'atomic';")
			digest := sha256.Sum256(code)
			archiveKey := lambda.CodeArchiveKey{Scope: key.Scope, SHA256: base64.StdEncoding.EncodeToString(digest[:])}
			s := service.New(service.Config{Repository: repo, PublicEndpoint: "http://localhost", APIEvents: apievents.New(events)})
			t.Cleanup(func() { _ = s.Close() })
			in := &api.PublishLayerVersionInput{LayerName: new(api.LayerName(key.Name)), Content: &api.LayerVersionContentInput{ZipFile: code}}
			abort := errors.New("abort layer transaction")
			if err := repo.Update(owned, func(tx lambda.Transaction) error {
				if _, wire := storedAliasCommand(t, s, tx.Context(), "PublishLayerVersion", in); wire != nil {
					return wire
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatal(err)
			}
			if err := repo.View(ctx, func(r lambda.Reader) error {
				if _, err := r.OwnedLayerVersion(key, owner); !errors.Is(err, lambda.ErrNotFound) {
					t.Fatalf("rollback retained receipt: %v", err)
				}
				if _, err := r.LayerVersion(lambda.LayerVersionKey{LayerKey: key, Version: 1}); !errors.Is(err, lambda.ErrNotFound) {
					t.Fatalf("rollback retained publication: %v", err)
				}
				if _, err := r.CodeArchive(archiveKey); !errors.Is(err, lambda.ErrNotFound) {
					t.Fatalf("rollback retained downloaded artifact: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if committed, err := events.Read(ctx, 0, 10); err != nil || len(committed) != 0 {
				t.Fatalf("rolled-back publication retained API event: %+v %v", committed, err)
			}
			first := layerOwnerPublication(t, s, owned, in)
			if *first.Version != 1 {
				t.Fatalf("rollback consumed generation: %d", *first.Version)
			}
			deletion := &api.DeleteLayerVersionInput{LayerName: in.LayerName, VersionNumber: first.Version}
			if err := repo.Update(owned, func(tx lambda.Transaction) error {
				if _, wire := storedAliasCommand(t, s, tx.Context(), "DeleteLayerVersion", deletion); wire != nil {
					return wire
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatal(err)
			}
			if err := repo.View(ctx, func(r lambda.Reader) error {
				v, err := r.OwnedLayerVersion(key, owner)
				if err != nil || v.Key.Version != 1 || v.CodeSHA256 != archiveKey.SHA256 {
					t.Fatalf("rolled-back deletion lost publication: %+v %v", v, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			committed, err := events.Read(ctx, 0, 10)
			if err != nil || len(committed) != 1 || committed[0].APICallCompleted == nil || committed[0].APICallCompleted.EventName != "PublishLayerVersion20181031" || committed[0].APICallCompleted.ErrorCode != "" {
				t.Fatalf("publication and journal diverged: %+v %v", committed, err)
			}
			call := committed[0].APICallCompleted
			for _, private := range []string{owner.StackID, owner.LogicalID, owner.Token} {
				if strings.Contains(string(call.RequestParameters), private) || strings.Contains(string(call.ResponseElements), private) {
					t.Fatal("layer publication leaked private ownership onto wire")
				}
			}
			if _, wire := storedAliasCommand(t, s, owned, "DeleteLayerVersion", deletion); wire != nil {
				t.Fatal(wire)
			}
			if committed, err := events.Read(ctx, 0, 10); err != nil || len(committed) != 2 || committed[1].APICallCompleted == nil || committed[1].APICallCompleted.EventName != "DeleteLayerVersion20181031" {
				t.Fatalf("delete lost committed event: %+v %v", committed, err)
			}
		})
	}
}

type layerOwnerPolicies struct{ allow atomic.Bool }

func (p *layerOwnerPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	if !p.allow.Load() {
		return authorization.PolicySet{}, nil
	}
	return authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"lambda:*","Resource":"*"}}`}}}, nil
}

func TestLayerOwnerCurrentIAMFencesRecoveryAndExternalLoading(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		key := lambda.LayerKey{Scope: deployment().Key.Scope, Name: "authorized-layer"}
		ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
		metadata := awsctx.FromContext(ctx)
		metadata.PrincipalARN, metadata.PrincipalID = "arn:aws:iam::111111111111:user/operator", "AIDA11111111111111111"
		ctx = awsctx.WithMetadata(ctx, metadata)
		owner := lambda.LayerVersionOwner{StackID: "stack-a", LogicalID: "Layer", Token: "request-a"}
		owned := service.WithLayerVersionOwner(ctx, owner)
		identity := &layerOwnerPolicies{}
		identity.allow.Store(true)
		code := layerOwnerZIP(t, "exports.value = 'authorized';")
		var reads atomic.Int32
		var revokeOnRead atomic.Bool
		revokeOnRead.Store(true)
		source := layerOwnerSource{read: func(context.Context) ([]byte, *awswire.Error) {
			reads.Add(1)
			if revokeOnRead.Load() {
				identity.allow.Store(false)
			}
			return code, nil
		}}
		config := service.Config{Repository: repo, CodeSource: source, PublicEndpoint: "http://localhost", Authorizer: authorization.New(identity, nil)}
		s := service.New(config)
		t.Cleanup(func() { _ = s.Close() })
		in := &api.PublishLayerVersionInput{LayerName: new(api.LayerName(key.Name)), Content: &api.LayerVersionContentInput{S3Bucket: new(api.S3Bucket("source")), S3Key: new(api.S3Key("layer.zip"))}}
		_, wire := storedAliasCommand(t, s, owned, "PublishLayerVersion", in)
		if wire == nil || wire.Code != "AccessDeniedException" {
			t.Fatalf("publication ignored revocation during download: %v", wire)
		}
		if err := repo.View(ctx, func(r lambda.Reader) error {
			if _, err := r.OwnedLayerVersion(key, owner); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("revoked publication retained receipt: %v", err)
			}
			if _, err := r.LayerVersion(lambda.LayerVersionKey{LayerKey: key, Version: 1}); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("revoked publication retained catalog row: %v", err)
			}
			digest := sha256.Sum256(code)
			if _, err := r.CodeArchive(lambda.CodeArchiveKey{Scope: key.Scope, SHA256: base64.StdEncoding.EncodeToString(digest[:])}); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("revoked publication retained artifact: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		revokeOnRead.Store(false)
		identity.allow.Store(true)
		first := layerOwnerPublication(t, s, owned, in)
		if *first.Version != 1 {
			t.Fatalf("revoked publication consumed generation: %d", *first.Version)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = service.New(config)
		identity.allow.Store(false)
		before := reads.Load()
		_, wire = storedAliasCommand(t, s, owned, "PublishLayerVersion", in)
		if wire == nil || wire.Code != "AccessDeniedException" || reads.Load() != before {
			t.Fatalf("revoked recovery bypassed IAM or reloaded source: %v; reads %d -> %d", wire, before, reads.Load())
		}
		_, wire = storedAliasCommand(t, s, owned, "DeleteLayerVersion", &api.DeleteLayerVersionInput{LayerName: in.LayerName, VersionNumber: first.Version})
		if wire == nil || wire.Code != "AccessDeniedException" {
			t.Fatalf("owned delete bypassed current IAM: %v", wire)
		}
		identity.allow.Store(true)
		sameLayerPublication(t, layerOwnerPublication(t, s, owned, in), first)
		if reads.Load() != before {
			t.Fatalf("restored-authority receipt recovery reloaded source: %d -> %d", before, reads.Load())
		}
	})
}
