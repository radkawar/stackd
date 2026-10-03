package ecr

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ecr"
	"stackd/storage/memory"
)

type transactionalEventPublisher struct {
	store    *memory.Store[[]Event]
	rejected error
}

func (p *transactionalEventPublisher) PublishEvent(ctx context.Context, event Event) error {
	return p.store.Update(ctx, func(events *[]Event, _ *memory.Transaction) error {
		*events = append(*events, event)
		return p.rejected
	})
}

func (p *transactionalEventPublisher) snapshot(t *testing.T) []Event {
	t.Helper()
	var result []Event
	if err := p.store.View(t.Context(), func(events *[]Event, _ *memory.Transaction) error {
		result = slices.Clone(*events)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func eventFixture(t *testing.T) (*Service, *MemoryRepository, *transactionalEventPublisher, RepositoryKey) {
	t.Helper()
	domain := memory.NewDomain()
	repository := NewMemoryRepository(domain)
	publisher := &transactionalEventPublisher{store: memory.New(domain, []Event{}, slices.Clone[[]Event])}
	service := New(Config{Repository: repository, Events: publisher, ReplicationRoles: &replicationTestRoles{}, Clock: clock.NewManual(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)), PublicEndpoint: "http://localhost:4566"})
	t.Cleanup(func() { service.Close() })
	key := RepositoryKey{Scope: Scope{"aws", "123456789012", "us-east-1"}, Name: "team/events"}
	if err := repository.Update(lifecycleTestContext(key.Scope), func(tx Transaction) error {
		_, err := service.createRepository(tx, &api.CreateRepositoryInput{RepositoryName: str[api.RepositoryName](key.Name)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return service, repository, publisher, key
}

func TestImageActionEventsShareMutationTransaction(t *testing.T) {
	service, repository, publisher, key := eventFixture(t)
	digest := replicationPutImage(t, service, repository, key, `{"version":"one"}`, "latest")
	ctx := lifecycleTestContext(key.Scope)
	in := &api.BatchGetImageInput{RepositoryName: str[api.RepositoryName](key.Name), ImageIds: api.ImageIdentifierList{{ImageTag: str[api.ImageTag]("latest")}}}
	publisher.rejected = errors.New("event admission rejected")
	err := repository.Attempt(ctx, func(tx Transaction) error {
		out, err := service.batchGetImage(tx, in)
		if err != nil {
			return err
		}
		_, err = service.putImage(tx, &api.PutImageInput{RepositoryName: in.RepositoryName, ImageManifest: out.Images[0].ImageManifest, ImageTag: str[api.ImageTag]("rolled-back")})
		return err
	})
	if !errors.Is(err, publisher.rejected) {
		t.Fatalf("push rejection = %v", err)
	}
	replicationAssertTags(t, repository, key, digest, "latest")
	remove := &api.BatchDeleteImageInput{RepositoryName: in.RepositoryName, ImageIds: api.ImageIdentifierList{{ImageTag: str[api.ImageTag]("latest")}, {ImageTag: str[api.ImageTag]("missing")}}}
	err = repository.Attempt(ctx, func(tx Transaction) error {
		_, err := service.batchDeleteImage(tx, remove)
		return err
	})
	if !errors.Is(err, publisher.rejected) {
		t.Fatalf("delete rejection = %v", err)
	}
	replicationAssertTags(t, repository, key, digest, "latest")
	publisher.rejected = nil
	if err = repository.Attempt(ctx, func(tx Transaction) error {
		out, err := service.batchDeleteImage(tx, remove)
		if err == nil && (len(out.ImageIds) != 1 || len(out.Failures) != 1 || value(out.Failures[0].FailureCode) != "ImageNotFound") {
			t.Fatalf("partial image deletion = %+v", out)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = repository.View(ctx, func(tx Reader) error {
		_, err := tx.Image(ImageKey{key, digest})
		return err
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted image remained present: %v", err)
	}
	events := publisher.snapshot(t)
	if len(events) != 2 {
		t.Fatalf("committed push/delete events = %+v", events)
	}
	for i, action := range []string{"PUSH", "DELETE"} {
		var detail imageActionDetail
		if err := json.Unmarshal(events[i].Detail, &detail); err != nil {
			t.Fatal(err)
		}
		if events[i].Scope != key.Scope || events[i].DetailType != "ECR Image Action" || len(events[i].Resources) != 0 || !events[i].At.Equal(service.clock.Now()) || detail != (imageActionDetail{Result: "SUCCESS", RepositoryName: key.Name, ImageDigest: digest, ActionType: action, ImageTag: "latest"}) {
			t.Fatalf("image action event = %+v / %+v", events[i], detail)
		}
	}
}

func TestReplicationEventsCommitWithDestination(t *testing.T) {
	service, repository, publisher, source := eventFixture(t)
	destination := source
	destination.Region = "us-west-2"
	if err := repository.Update(lifecycleTestContext(source.Scope), func(tx Transaction) error {
		_, err := service.putReplicationConfiguration(tx, &api.PutReplicationConfigurationInput{ReplicationConfiguration: &api.ReplicationConfiguration{Rules: api.ReplicationRuleList{{Destinations: api.ReplicationDestinationList{{Region: str[api.Region](destination.Region), RegistryId: str[api.RegistryId](destination.AccountID)}}}}}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	content := `{"version":"one"}`
	digest := replicationPutImage(t, service, repository, source, content, "a", "b")
	publisher.rejected = errors.New("event admission rejected")
	replicationRun(t, service)
	if err := repository.View(t.Context(), func(tx Reader) error {
		_, err := tx.Repository(destination)
		return err
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed publication left a replica: %v", err)
	}
	if events := publisher.snapshot(t); len(events) != 2 {
		t.Fatalf("failed replication retained an event: %+v", events)
	}
	publisher.rejected = nil
	replicationPutImage(t, service, repository, source, content, "c")
	replicationRun(t, service)
	replicationAssertTags(t, repository, destination, digest, "a", "b", "c")
	events := publisher.snapshot(t)
	if len(events) != 6 {
		t.Fatalf("committed push/replication events = %+v", events)
	}
	for i, tag := range []string{"a", "b", "c"} {
		event := events[i+3]
		var detail replicationActionDetail
		if err := json.Unmarshal(event.Detail, &detail); err != nil {
			t.Fatal(err)
		}
		if event.Scope != destination.Scope || event.DetailType != "ECR Replication Action" || !slices.Equal(event.Resources, []string{repositoryARN(destination)}) || detail != (replicationActionDetail{Result: "SUCCESS", RepositoryName: destination.Name, ImageDigest: digest, SourceAccount: source.AccountID, SourceRegion: source.Region, ActionType: "REPLICATE", ImageTag: tag}) {
			t.Fatalf("replication event = %+v / %+v", event, detail)
		}
	}
}
