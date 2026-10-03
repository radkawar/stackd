package lambda

import (
	"archive/zip"
	"bytes"
	"errors"
	"reflect"
	"testing"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/journal"
	"stackd/storage/memory"
)

func TestLayerOwnerEventFailureRollsBackArtifactReceiptAndAllocation(t *testing.T) {
	domain := memory.NewDomain()
	repo := NewMemoryRepository(domain)
	events := journal.NewMemory(domain)
	key := LayerKey{Scope: Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "atomic-layer"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.Account, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: key.Account})
	owner := LayerVersionOwner{StackID: "stack-a", LogicalID: "Layer", Token: "request-a"}
	owned := WithLayerVersionOwner(ctx, owner)
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("python/owned.py")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("value = 'immutable'\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	in := &api.PublishLayerVersionInput{LayerName: new(api.LayerName(key.Name)), Content: &api.LayerVersionContentInput{ZipFile: archive.Bytes()}, Description: new(api.Description("immutable"))}
	s := aliasOwnerService(t, Config{Repository: repo, PublicEndpoint: "http://localhost", APIEvents: rejectedAliasEvents{apievents.New(events)}})
	_, wire := s.publishLayerVersion(owned, in)
	requireAliasOwnerCode(t, wire, "ServiceException")
	archiveKey := deploymentArchive(key.Scope, archive.Bytes(), s.clock.Now()).Key
	if err := repo.View(ctx, func(r Reader) error {
		if _, err := r.OwnedLayerVersion(key, owner); !errors.Is(err, ErrNotFound) {
			t.Fatalf("event failure retained owner receipt: %v", err)
		}
		if _, err := r.LayerVersion(LayerVersionKey{LayerKey: key, Version: 1}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("event failure retained publication: %v", err)
		}
		if _, err := r.CodeArchive(archiveKey); !errors.Is(err, ErrNotFound) {
			t.Fatalf("event failure retained artifact: %v", err)
		}
		if _, err := r.CodeSigningKey(key.Scope); !errors.Is(err, ErrNotFound) {
			t.Fatalf("event failure retained download credentials: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := events.Read(ctx, 0, 10); err != nil || len(got) != 0 {
		t.Fatalf("event failure committed API event: %+v %v", got, err)
	}
	s = aliasOwnerService(t, Config{Repository: repo, PublicEndpoint: "http://localhost", APIEvents: apievents.New(events)})
	first, wire := s.publishLayerVersion(owned, in)
	if wire != nil || *first.Version != 1 {
		t.Fatalf("event failure consumed publication allocation: %+v %v", first, wire)
	}
	var want LayerVersionRecord
	if err := repo.View(ctx, func(r Reader) error {
		var err error
		want, err = r.OwnedLayerVersion(key, owner)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s = aliasOwnerService(t, Config{Repository: repo, PublicEndpoint: "http://localhost", APIEvents: rejectedAliasEvents{apievents.New(events)}})
	in.Content = &api.LayerVersionContentInput{S3Bucket: new(api.S3Bucket("deleted-source")), S3Key: new(api.S3Key("layer.zip"))}
	_, wire = s.publishLayerVersion(owned, in)
	requireAliasOwnerCode(t, wire, "ServiceException")
	_, wire = s.deleteLayerVersion(owned, &api.DeleteLayerVersionInput{LayerName: in.LayerName, VersionNumber: first.Version})
	requireAliasOwnerCode(t, wire, "ServiceException")
	if err := repo.View(ctx, func(r Reader) error {
		got, err := r.OwnedLayerVersion(key, owner)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("failed recovery/delete changed immutable receipt: %+v %v; want %+v", got, err, want)
		}
		stored, err := r.CodeArchive(archiveKey)
		if err != nil || !bytes.Equal(stored.Code, archive.Bytes()) {
			t.Fatalf("failed recovery/delete changed downloaded bytes: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := events.Read(ctx, 0, 10); err != nil || len(got) != 1 || got[0].APICallCompleted == nil || got[0].APICallCompleted.EventName != "PublishLayerVersion20181031" {
		t.Fatalf("failed recovery/delete committed API event: %+v %v", got, err)
	}
}
