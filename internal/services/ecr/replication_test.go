package ecr

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ecr"
)

type replicationTestRoles struct{ rejected error }

func (*replicationTestRoles) Ensure(context.Context) error { return nil }
func (r *replicationTestRoles) Context(ctx context.Context, _ Scope) (context.Context, error) {
	return ctx, r.rejected
}

// Interleave accepted commands only outside actual repository transactions.
// The hooks model another caller winning the lock before delivery or directly
// after a failed delivery releases it, without goroutine timing or sleeps.
type replicationBoundaryRepository struct {
	Repository
	beforeWrite, afterWrite func()
}
type replicationBoundaryKey struct{}

func (r *replicationBoundaryRepository) write(ctx context.Context, fn func(Transaction) error, attempt bool) error {
	outer := ctx.Value(replicationBoundaryKey{}) == nil
	if outer && r.beforeWrite != nil {
		hook := r.beforeWrite
		r.beforeWrite = nil
		hook()
	}
	ctx = context.WithValue(ctx, replicationBoundaryKey{}, true)
	var err error
	if attempt {
		err = r.Repository.Attempt(ctx, fn)
	} else {
		err = r.Repository.Update(ctx, fn)
	}
	if outer && r.afterWrite != nil {
		hook := r.afterWrite
		r.afterWrite = nil
		hook()
	}
	return err
}
func (r *replicationBoundaryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return r.write(ctx, fn, false)
}
func (r *replicationBoundaryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return r.write(ctx, fn, true)
}

func replicationFixture(t *testing.T) (*Service, *MemoryRepository, *replicationTestRoles, RepositoryKey, RepositoryKey) {
	t.Helper()
	repository := NewMemoryRepository(nil)
	roles := &replicationTestRoles{}
	service := New(Config{Repository: repository, ReplicationRoles: roles, Clock: clock.NewManual(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)), PublicEndpoint: "http://localhost:4566"})
	t.Cleanup(func() { service.Close() })
	source := RepositoryKey{Scope: Scope{"aws", "123456789012", "us-east-1"}, Name: "team/images"}
	destination := source
	destination.Region = "us-west-2"
	ctx := lifecycleTestContext(source.Scope)
	if err := repository.Update(ctx, func(tx Transaction) error {
		if _, err := service.createRepository(tx, &api.CreateRepositoryInput{RepositoryName: str[api.RepositoryName](source.Name)}); err != nil {
			return err
		}
		_, err := service.putReplicationConfiguration(tx, &api.PutReplicationConfigurationInput{ReplicationConfiguration: &api.ReplicationConfiguration{Rules: api.ReplicationRuleList{{Destinations: api.ReplicationDestinationList{{Region: str[api.Region](destination.Region), RegistryId: str[api.RegistryId](destination.AccountID)}}}}}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return service, repository, roles, source, destination
}

func replicationPutImage(t *testing.T, service *Service, repository Repository, key RepositoryKey, content string, tags ...string) string {
	t.Helper()
	config := []byte(content)
	configDigest := digestBytes(config)
	manifest, err := json.Marshal(manifestDocument{SchemaVersion: 2, MediaType: ociManifest, Config: &descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: configDigest, Size: int64(len(config))}, Layers: []descriptor{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(lifecycleTestContext(key.Scope), func(tx Transaction) error {
		repo, err := tx.Repository(key)
		if err != nil {
			return err
		}
		payload, err := service.sealPayload(tx.Context(), repo, "blob:"+configDigest, config)
		if err != nil {
			return err
		}
		if err = tx.PutBlob(BlobRecord{Key: ImageKey{key, configDigest}, Payload: payload, Size: int64(len(config))}); err != nil {
			return err
		}
		for _, tag := range tags {
			if _, err = service.putImage(tx, &api.PutImageInput{RepositoryName: str[api.RepositoryName](key.Name), ImageManifest: str[api.ImageManifest](string(manifest)), ImageTag: str[api.ImageTag](tag)}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return digestBytes(manifest)
}

func replicationRun(t *testing.T, service *Service) {
	t.Helper()
	jobs := replicationJobs{service}
	job, found, err := jobs.Next(context.Background())
	if err != nil || !found {
		t.Fatalf("next replication = %v, %v", found, err)
	}
	if err := jobs.Run(context.Background(), job); err != nil {
		t.Fatal(err)
	}
}

func replicationAssertTags(t *testing.T, repository Repository, key RepositoryKey, digest string, want ...string) {
	t.Helper()
	if err := repository.View(context.Background(), func(tx Reader) error {
		image, err := tx.Image(ImageKey{key, digest})
		if err == nil && !slices.Equal(image.Tags, want) {
			t.Errorf("%s %s tags = %q, want %q", key.Region, digest, image.Tags, want)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReplicationMovesAllTags(t *testing.T) {
	service, repository, _, source, destination := replicationFixture(t)
	old := replicationPutImage(t, service, repository, source, `{"version":"old"}`, "a", "b")
	replicationRun(t, service)
	fresh := replicationPutImage(t, service, repository, source, `{"version":"new"}`, "a", "b")
	replicationRun(t, service)
	replicationAssertTags(t, repository, destination, old)
	replicationAssertTags(t, repository, destination, fresh, "a", "b")
}

func TestReplicationDeliveryUsesCurrentWork(t *testing.T) {
	service, repository, _, source, destination := replicationFixture(t)
	content := `{"version":"one"}`
	digest := replicationPutImage(t, service, repository, source, content, "a")
	service.repository = &replicationBoundaryRepository{Repository: repository, beforeWrite: func() {
		replicationPutImage(t, service, repository, source, content, "b")
	}}
	replicationRun(t, service)
	replicationAssertTags(t, repository, destination, digest, "a", "b")
	if _, pending, err := (replicationJobs{service}).Next(context.Background()); err != nil || pending {
		t.Fatalf("replication completion = pending %v, error %v", pending, err)
	}
}

func TestReplicationFailurePreservesNewWork(t *testing.T) {
	service, repository, roles, source, destination := replicationFixture(t)
	content := `{"version":"one"}`
	digest := replicationPutImage(t, service, repository, source, content, "a")
	roles.rejected = failure("AccessDeniedException", "Replication role is denied")
	service.repository = &replicationBoundaryRepository{Repository: repository, afterWrite: func() {
		replicationPutImage(t, service, repository, source, content, "b")
	}}
	replicationRun(t, service)
	roles.rejected = nil
	replicationRun(t, service)
	replicationAssertTags(t, repository, destination, digest, "a", "b")
}

func TestReplicationFailureRollsBackDestination(t *testing.T) {
	service, repository, _, source, destination := replicationFixture(t)
	digest := replicationPutImage(t, service, repository, source, `{"version":"one"}`, "a")
	if err := repository.Update(context.Background(), func(tx Transaction) error {
		image, err := tx.Image(ImageKey{source, digest})
		if err != nil {
			return err
		}
		image.Payload = []byte("invalid ciphertext")
		return tx.PutImage(image)
	}); err != nil {
		t.Fatal(err)
	}
	replicationRun(t, service)
	if err := repository.View(context.Background(), func(tx Reader) error {
		if _, err := tx.Repository(destination); !errors.Is(err, ErrNotFound) {
			t.Fatalf("failed delivery retained destination: %v", err)
		}
		rows, err := tx.Replications()
		if err == nil && (len(rows) != 1 || rows[0].Status != "FAILED" || rows[0].Error == "") {
			t.Fatalf("failed replication = %+v", rows)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, pending, err := (replicationJobs{service}).Next(context.Background()); err != nil || pending {
		t.Fatalf("failed replication remained pending: %v, %v", pending, err)
	}
}

func TestReplicationStatusTransitionsAndCurrentAuthority(t *testing.T) {
	service, repository, roles, source, destination := replicationFixture(t)
	content := `{"version":"one"}`
	digest := replicationPutImage(t, service, repository, source, content, "a")
	ctx := lifecycleTestContext(source.Scope)
	input := &api.DescribeImageReplicationStatusInput{RepositoryName: str[api.RepositoryName](source.Name), ImageId: &api.ImageIdentifier{ImageTag: str[api.ImageTag]("a")}}
	status := func(want, failureCode string) {
		t.Helper()
		if err := repository.Update(ctx, func(tx Transaction) error {
			out, err := service.describeImageReplicationStatus(tx, input)
			if err != nil {
				return err
			}
			if value(out.RepositoryName) != source.Name || value(out.ImageId.ImageDigest) != digest || value(out.ImageId.ImageTag) != "a" {
				t.Fatalf("status image = %+v", out)
			}
			if len(out.ReplicationStatuses) != 1 {
				t.Fatalf("status destinations = %+v", out.ReplicationStatuses)
			}
			got := out.ReplicationStatuses[0]
			if value(got.Region) != destination.Region || value(got.RegistryId) != destination.AccountID || value(got.Status) != want || value(got.FailureCode) != failureCode {
				t.Fatalf("replication status = %+v, want %s / %s", got, want, failureCode)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	status("IN_PROGRESS", "")
	roles.rejected = failure("AccessDeniedException", "Replication role denied")
	replicationRun(t, service)
	status("FAILED", "AccessDeniedException")
	roles.rejected = nil
	replicationPutImage(t, service, repository, source, content, "b")
	status("IN_PROGRESS", "")
	replicationRun(t, service)
	status("COMPLETE", "")
	// An identically named repository in another Region must not expose the
	// source's work, even when it contains the same replicated digest.
	if err := repository.Update(lifecycleTestContext(destination.Scope), func(tx Transaction) error {
		out, err := service.describeImageReplicationStatus(tx, input)
		if err == nil && len(out.ReplicationStatuses) != 0 {
			t.Fatalf("destination exposed source work: %+v", out.ReplicationStatuses)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(ctx, func(tx Transaction) error {
		repo, err := tx.Repository(source)
		if err != nil {
			return err
		}
		repo.Policy = authorization.BoundPolicy{Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"ecr:DescribeImageReplicationStatus","Resource":"*"}]}`}
		return tx.PutRepository(repo)
	}); err != nil {
		t.Fatal(err)
	}
	err := repository.Attempt(ctx, func(tx Transaction) error {
		_, err := service.describeImageReplicationStatus(tx, input)
		return err
	})
	if err == nil || wireError(err).Code != "AccessDeniedException" {
		t.Fatalf("current repository denial = %v", err)
	}
}

func TestReplicationStatusMissingImage(t *testing.T) {
	service, repository, _, source, _ := replicationFixture(t)
	for _, id := range []*api.ImageIdentifier{nil, {}, {ImageTag: str[api.ImageTag]("missing")}, {ImageDigest: str[api.ImageDigest]("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}} {
		err := repository.Attempt(lifecycleTestContext(source.Scope), func(tx Transaction) error {
			_, err := service.describeImageReplicationStatus(tx, &api.DescribeImageReplicationStatusInput{RepositoryName: str[api.RepositoryName](source.Name), ImageId: id})
			return err
		})
		want := "ImageNotFoundException"
		if id == nil || id.ImageTag == nil && id.ImageDigest == nil {
			want = "InvalidParameterException"
		}
		if err == nil || wireError(err).Code != want {
			t.Fatalf("image %v rejected with %v, want %s", id, err, want)
		}
	}
}
