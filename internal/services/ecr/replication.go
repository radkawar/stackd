package ecr

import (
	"context"
	"errors"
	"slices"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"strings"
)

const ReplicationServicePrincipal = "replication.ecr.amazonaws.com"
const ReplicationServiceRoleName = "AWSServiceRoleForECRReplication"

type ReplicationRoles interface {
	Ensure(context.Context) error
	Context(context.Context, Scope) (context.Context, error)
}

func replicationID(k ReplicationKey) string {
	return repositoryARN(k.Source.Repository) + "@" + k.Source.Digest + "/" + k.Destination.Partition + "/" + k.Destination.AccountID + "/" + k.Destination.Region
}
func (s *Service) putReplicationConfiguration(tx Transaction, in *api.PutReplicationConfigurationInput) (*api.PutReplicationConfigurationOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "PutReplicationConfiguration", RepositoryRecord{Key: RepositoryKey{Scope: scope}}, nil); err != nil {
		return nil, err
	}
	if in.ReplicationConfiguration == nil || len(in.ReplicationConfiguration.Rules) > 10 {
		return nil, failure("InvalidParameterException", "A replication configuration supports at most ten rules.")
	}
	for _, rule := range in.ReplicationConfiguration.Rules {
		if len(rule.Destinations) == 0 || len(rule.Destinations) > 25 {
			return nil, failure("InvalidParameterException", "A replication rule requires one to 25 destinations.")
		}
		for _, d := range rule.Destinations {
			if value(d.Region) == "" || len(value(d.RegistryId)) != 12 || (value(d.Region) == scope.Region && value(d.RegistryId) == scope.AccountID) {
				return nil, failure("InvalidParameterException", "Invalid replication destination.")
			}
		}
		for _, f := range rule.RepositoryFilters {
			if value(f.FilterType) != "PREFIX_MATCH" || value(f.Filter) == "" {
				return nil, failure("InvalidParameterException", "Replication repository filters must use PREFIX_MATCH.")
			}
		}
	}
	if len(in.ReplicationConfiguration.Rules) > 0 {
		if s.replicationRoles == nil {
			return nil, failure("ServerException", "ECR replication requires its IAM service-linked-role issuer.")
		}
		if err := s.replicationRoles.Ensure(tx.Context()); err != nil {
			return nil, err
		}
	}
	r, err := s.registry(tx, scope)
	if err != nil {
		return nil, err
	}
	r.Replication = api.CloneReplicationConfiguration(*in.ReplicationConfiguration)
	if err = tx.PutRegistry(r); err != nil {
		return nil, err
	}
	return &api.PutReplicationConfigurationOutput{ReplicationConfiguration: &r.Replication}, nil
}
func (s *Service) replicateImage(tx Transaction, repo RepositoryRecord, image ImageRecord) error {
	registry, err := s.registry(tx, repo.Key.Scope)
	if err != nil {
		return err
	}
	seen := map[Scope]bool{}
	for _, rule := range registry.Replication.Rules {
		matches := len(rule.RepositoryFilters) == 0
		for _, filter := range rule.RepositoryFilters {
			matches = matches || strings.HasPrefix(repo.Key.Name, value(filter.Filter))
		}
		if !matches {
			continue
		}
		for _, d := range rule.Destinations {
			destination := Scope{repo.Key.Partition, value(d.RegistryId), value(d.Region)}
			if seen[destination] {
				continue
			}
			seen[destination] = true
			work := ReplicationRecord{Key: ReplicationKey{image.Key, destination}, Tags: slices.Clone(image.Tags), Due: s.clock.Now(), Status: "IN_PROGRESS", Origin: awsctx.FromContext(tx.Context())}
			if err = tx.PutReplication(work); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) describeImageReplicationStatus(tx Transaction, in *api.DescribeImageReplicationStatusInput) (*api.DescribeImageReplicationStatusOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "DescribeImageReplicationStatus")
	if err != nil {
		return nil, err
	}
	if in.ImageId == nil {
		return nil, failure("InvalidParameterException", "An image identifier is required.")
	}
	image, err := resolveImage(tx, repo.Key, *in.ImageId)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ImageNotFoundException", "The specified image does not exist.")
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.Replications()
	if err != nil {
		return nil, err
	}
	statuses := api.ImageReplicationStatusList{}
	for _, work := range rows {
		if work.Key.Source != image.Key {
			continue
		}
		status := api.ImageReplicationStatus{
			Region:     str[api.Region](work.Key.Destination.Region),
			RegistryId: str[api.RegistryId](work.Key.Destination.AccountID),
			Status:     str[api.ReplicationStatus](work.Status),
		}
		if work.Status == "FAILED" {
			code, _, _ := strings.Cut(work.Error, ": ")
			status.FailureCode = str[api.ReplicationError](code)
		}
		statuses = append(statuses, status)
	}
	return &api.DescribeImageReplicationStatusOutput{
		RepositoryName:      str[api.RepositoryName](repo.Key.Name),
		ImageId:             &api.ImageIdentifier{ImageDigest: str[api.ImageDigest](image.Key.Digest), ImageTag: in.ImageId.ImageTag},
		ReplicationStatuses: statuses,
	}, nil
}

type replicationJobs struct{ s *Service }

func (j replicationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var work ReplicationRecord
	found := false
	err := j.s.repository.View(ctx, func(tx Reader) error {
		rows, err := tx.Replications()
		if err != nil {
			return err
		}
		for _, v := range rows {
			if v.Status == "IN_PROGRESS" && (!found || v.Due.Before(work.Due) || v.Due.Equal(work.Due) && replicationID(v.Key) < replicationID(work.Key)) {
				work = v
				found = true
			}
		}
		return nil
	})
	return scheduler.Job{Key: replicationID(work.Key), Due: work.Due}, found, err
}
func (j replicationJobs) Run(ctx context.Context, job scheduler.Job) error {
	// Selecting current work, copying and publishing its outcome share one
	// write transaction. Delivery uses a savepoint so failure rolls back all
	// destination changes before marking that same work FAILED.
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.Replications()
		if err != nil {
			return err
		}
		var work ReplicationRecord
		found := false
		for _, v := range rows {
			if v.Status == "IN_PROGRESS" && replicationID(v.Key) == job.Key && v.Due.Equal(job.Due) && !v.Due.After(j.s.clock.Now()) {
				work = v
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		deliveryCtx := awsctx.WithMetadata(tx.Context(), work.Origin)
		err = j.s.repository.Attempt(deliveryCtx, func(attempt Transaction) error {
			if j.s.replicationRoles == nil {
				return failure("ServerException", "ECR replication role issuer is unavailable.")
			}
			roleCtx, err := j.s.replicationRoles.Context(attempt.Context(), work.Key.Source.Repository.Scope)
			if err != nil {
				return err
			}
			return j.s.repository.Update(roleCtx, func(dest Transaction) error {
				source, err := dest.Repository(work.Key.Source.Repository)
				if err != nil {
					return err
				}
				if err = j.s.copyReplica(dest, source, work.Key.Source.Digest, work.Key.Destination, work.Tags, map[string]bool{}); err != nil {
					return err
				}
				work.Status = "COMPLETE"
				work.Error = ""
				if err = dest.PutReplication(work); err != nil {
					return err
				}
				return j.s.recordServiceEvent(dest.Context(), "ReplicateImage", source, map[string]any{"imageDigest": work.Key.Source.Digest, "destinationRegistryId": work.Key.Destination.AccountID, "destinationRegion": work.Key.Destination.Region})
			})
		})
		if err == nil {
			return nil
		}
		rejected := wireError(err)
		work.Status = "FAILED"
		work.Error = rejected.Code + ": " + rejected.Message
		return tx.PutReplication(work)
	})
}
func (s *Service) copyReplica(tx Transaction, source RepositoryRecord, digest string, destination Scope, tags []string, visited map[string]bool) error {
	if visited[digest] {
		return nil
	}
	visited[digest] = true
	image, err := tx.Image(ImageKey{source.Key, digest})
	if err != nil {
		return err
	}
	key := RepositoryKey{destination, source.Key.Name}
	repo, err := tx.Repository(key)
	if errors.Is(err, ErrNotFound) {
		repo = RepositoryRecord{Key: key, ARN: repositoryARN(key), Created: s.clock.Now(), Mutability: "MUTABLE", EncryptionType: "AES256", Tags: map[string]string{}}
		if err = s.authorize(tx, "CreateRepository", repo, nil); err != nil {
			return err
		}
		repo, err = s.prepareRepositoryEncryption(tx.Context(), repo, "")
		if err != nil {
			return err
		}
		if err = tx.PutRepository(repo); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err = s.authorize(tx, "ReplicateImage", repo, nil); err != nil {
		return err
	}
	for _, child := range image.References {
		if err = s.copyReplica(tx, source, child, destination, nil, visited); err != nil {
			return err
		}
	}
	for _, digest := range image.Layers {
		if _, err = tx.Blob(ImageKey{repo.Key, digest}); err == nil {
			continue
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		blob, err := tx.Blob(ImageKey{source.Key, digest})
		if err != nil {
			return err
		}
		plain, err := s.openPayload(tx.Context(), source, "blob:"+digest, blob.Payload)
		if err != nil {
			return err
		}
		blob.Payload, err = s.sealPayload(tx.Context(), repo, "blob:"+digest, plain)
		if err != nil {
			return err
		}
		blob.Key.Repository = repo.Key
		if err = tx.PutBlob(blob); err != nil {
			return err
		}
	}
	plain, err := s.openPayload(tx.Context(), source, "manifest:"+digest, image.Payload)
	if err != nil {
		return err
	}
	image.Payload, err = s.sealPayload(tx.Context(), repo, "manifest:"+digest, plain)
	if err != nil {
		return err
	}
	image.Key.Repository = repo.Key
	image.Tags = nil
	image.Pushed = s.clock.Now()
	existing, err := tx.Image(image.Key)
	if err == nil {
		image = existing
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	rows, err := tx.Images(repo.Key)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		if slices.Contains(image.Tags, tag) {
			continue
		}
		conflict := false
		for i := range rows {
			old := &rows[i]
			if old.Key.Digest != digest && slices.Contains(old.Tags, tag) {
				if tagImmutable(repo, tag) {
					conflict = true
					break
				}
				old.Tags = slices.DeleteFunc(old.Tags, func(v string) bool { return v == tag })
				if err = tx.PutImage(*old); err != nil {
					return err
				}
			}
		}
		if !conflict {
			image.Tags = append(image.Tags, tag)
		}
	}
	slices.Sort(image.Tags)
	if err = tx.PutImage(image); err != nil {
		return err
	}
	if s.events == nil {
		return nil
	}
	tagged := false
	for _, tag := range tags {
		if !slices.Contains(image.Tags, tag) {
			continue
		}
		if err = s.publishReplicationAction(tx.Context(), source.Key.Scope, image, tag); err != nil {
			return err
		}
		tagged = true
	}
	if !tagged {
		return s.publishReplicationAction(tx.Context(), source.Key.Scope, image, "")
	}
	return nil
}
func (s *Service) WithReplicationRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []Scope) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		registries, err := tx.AllRegistries()
		if err != nil {
			return err
		}
		var active []Scope
		for _, registry := range registries {
			scope := registry.Scope
			if scope.Partition == partition && scope.AccountID == account && len(registry.Replication.Rules) > 0 {
				active = append(active, scope)
			}
		}
		work, err := tx.Replications()
		if err != nil {
			return err
		}
		for _, v := range work {
			scope := v.Key.Source.Repository.Scope
			if scope.Partition == partition && scope.AccountID == account && v.Status == "IN_PROGRESS" && !slices.Contains(active, scope) {
				active = append(active, scope)
			}
		}
		slices.SortFunc(active, func(a, b Scope) int { return strings.Compare(a.Region, b.Region) })
		return fn(tx.Context(), active)
	})
}
