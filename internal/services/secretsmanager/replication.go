package secretsmanager

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

// RegionAccess supplies Account Management's current destination-region state.
// Calls retain the originating transaction and do not persist caller credentials.
type RegionAccess interface {
	RegionEnabled(context.Context, string, string, time.Time) (bool, error)
}

func regionalSecretContext(ctx context.Context, region string) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.Region = region
	return awsctx.WithMetadata(ctx, metadata)
}

func regionalSecretARN(arn, region string) string {
	parts := strings.SplitN(arn, ":", 6)
	parts[3] = region
	return strings.Join(parts, ":")
}

func replicaSecretKey(primary SecretKey, region string) SecretKey {
	primary.Region = region
	return primary
}

func matchesReplica(secret SecretRecord, replica ReplicaRecord) bool {
	return secret.Key == replicaSecretKey(replica.Key.Primary, replica.Key.Region) &&
		secret.ARN == regionalSecretARN(replica.PrimaryARN, replica.Key.Region) &&
		secret.PrimaryRegion == replica.Key.Primary.Region && secret.Deleted == nil
}

func (s *Service) replicationStatus(r Reader, secret SecretRecord) (api.ReplicationStatusListType, error) {
	replicas, err := r.Replicas(secret.Key)
	if err != nil {
		return nil, err
	}
	out := make(api.ReplicationStatusListType, 0, len(replicas))
	for _, replica := range replicas {
		if replica.PrimaryARN != secret.ARN {
			continue
		}
		status := api.ReplicationStatusType{
			Region: str[api.RegionType](replica.Key.Region), KmsKeyId: str[api.KmsKeyIdType](replica.KMSKeyID),
			Status: str[api.StatusType](replica.Status),
		}
		if replica.Due != nil {
			status.Status = ptr(api.StatusTypeInProgress)
		} else if replica.StatusMessage != "" {
			status.StatusMessage = str[api.StatusMessageType](replica.StatusMessage)
		}
		target, err := r.Secret(replicaSecretKey(secret.Key, replica.Key.Region))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err == nil && matchesReplica(target, replica) {
			status.LastAccessedDate = target.LastAccessed
		}
		out = append(out, status)
	}
	return out, nil
}

func (s *Service) checkPrimaryDeletion(r Reader, secret SecretRecord) error {
	replicas, err := r.Replicas(secret.Key)
	if err != nil {
		return err
	}
	var regions []string
	for _, replica := range replicas {
		if replica.PrimaryARN == secret.ARN {
			regions = append(regions, replica.Key.Region)
		}
	}
	if len(regions) != 0 {
		return failure("InvalidParameterException", "You can't delete secret "+secret.ARN+" that still has replica regions ["+strings.Join(regions, ", ")+"].")
	}
	return nil
}

func validateReplicaRegion(secret SecretRecord, region string) error {
	if region == secret.Key.Region {
		return failure("InvalidParameterException", "You can't replicate a secret to the same Region as the primary secret.")
	}
	if awscatalog.RegionPartition(region) == "" || awscatalog.RegionPartition(region) != secret.Key.Partition {
		return failure("InvalidParameterException", "The replica Region must be a valid Region in the same AWS partition.")
	}
	return nil
}

func (s *Service) replicaRegionEnabled(ctx context.Context, secret SecretRecord, region string) error {
	if s.regions == nil {
		return failure("InternalServiceError", "Secrets Manager replication requires an Account RegionAccess provider.")
	}
	enabled, err := s.regions.RegionEnabled(ctx, secret.Key.AccountID, region, s.clock.Now().UTC())
	if err != nil {
		return err
	}
	if !enabled {
		return failure("InvalidParameterException", "The replica Region is not enabled for this account.")
	}
	return nil
}

func (s *Service) replicateSecretToRegions(tx Transaction, in *api.ReplicateSecretToRegionsInput) (*api.ReplicateSecretToRegionsOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	conditions := map[string][]string{}
	for _, region := range in.AddReplicaRegions {
		conditions["secretsmanager:AddReplicaRegions"] = append(conditions["secretsmanager:AddReplicaRegions"], value(region.Region))
	}
	if in.ForceOverwriteReplicaSecret != nil {
		conditions["secretsmanager:ForceOverwriteReplicaSecret"] = []string{strconv.FormatBool(bool(*in.ForceOverwriteReplicaSecret))}
	}
	if err := s.authorize(tx, "ReplicateSecretToRegions", secret, conditions); err != nil {
		return nil, err
	}
	if err := checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	statuses, err := s.replicate(tx, secret, in.AddReplicaRegions, in.ForceOverwriteReplicaSecret != nil && bool(*in.ForceOverwriteReplicaSecret))
	if err != nil {
		return nil, err
	}
	return &api.ReplicateSecretToRegionsOutput{ARN: str[api.SecretARNType](secret.ARN), ReplicationStatus: statuses}, nil
}

func (s *Service) replicate(tx Transaction, secret SecretRecord, regions api.AddReplicaRegionListType, force bool) (api.ReplicationStatusListType, error) {
	if len(regions) == 0 {
		return nil, failure("InvalidParameterException", "AddReplicaRegions must contain at least one region.")
	}
	for _, destination := range regions {
		region := value(destination.Region)
		if err := validateReplicaRegion(secret, region); err != nil {
			return nil, err
		}
		if destination.KmsKeyId != nil && (len(*destination.KmsKeyId) == 0 || len(*destination.KmsKeyId) > 2048) {
			return nil, failure("InvalidParameterException", "KmsKeyId must contain between 1 and 2048 characters.")
		}
	}
	// CreateSecret can have changed version metadata since taking its snapshot.
	// Never overwrite that state, or operate on a different secret incarnation.
	current, err := tx.Secret(secret.Key)
	if err != nil {
		return nil, err
	}
	if current.ARN != secret.ARN {
		return nil, ErrNotFound
	}
	secret = current
	if err := checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	secret.PrimaryRegion = secret.Key.Region
	secret.Changed = s.clock.Now().UTC()
	if err := tx.PutSecret(secret); err != nil {
		return nil, err
	}
	// Repository ordering is regional; sorting the request also makes KMS effects
	// deterministic independently of the client's AddReplicaRegions order.
	regions = slices.Clone(regions)
	slices.SortStableFunc(regions, func(a, b api.ReplicaRegionType) int { return strings.Compare(value(a.Region), value(b.Region)) })
	for index, destination := range regions {
		if index > 0 && value(destination.Region) == value(regions[index-1].Region) {
			continue
		}
		if err := s.prepareReplica(tx, secret, value(destination.Region), value(destination.KmsKeyId), force); err != nil {
			return nil, err
		}
	}
	return s.replicationStatus(tx, secret)
}

func (s *Service) failReplica(tx Transaction, replica ReplicaRecord, err error) error {
	due := s.clock.Now().UTC().Add(time.Second)
	replica.Status, replica.StatusMessage, replica.Due = "Failed", "Replication failed: "+wireError(err).Message, &due
	return tx.PutReplica(replica)
}

func (s *Service) queueReplica(tx Transaction, replica ReplicaRecord) error {
	// All value and metadata effects are committed now. The remaining work is
	// only the observable InProgress -> InSync transition, not delegated crypto.
	due := s.clock.Now().UTC().Add(time.Second)
	replica.Status, replica.StatusMessage, replica.Due = "InProgress", "", &due
	return tx.PutReplica(replica)
}

// copyReplicaMetadata intentionally retains regional identity, encryption,
// creation time and access history. Rotation executes only in the primary.
func copyReplicaMetadata(target, source SecretRecord) SecretRecord {
	target.Type, target.Description = source.Type, source.Description
	target.Tags, target.Policy = source.Tags, source.Policy
	target.Changed, target.OwningService = source.Changed, source.OwningService
	target.RotationEnabled, target.RotationLambdaARN = source.RotationEnabled, source.RotationLambdaARN
	target.RotationRules, target.LastRotated, target.NextRotation = source.RotationRules, source.LastRotated, source.NextRotation
	target.RotationDue = nil
	return target
}

// Destination replication requires Encrypt and GenerateDataKey, not Decrypt.
// validateKey is deliberately not used: it validates caller decryption access.
func (s *Service) validateReplicaKey(ctx context.Context, target SecretRecord, empty bool) error {
	configured := target.KMSKeyID
	if configured == "alias/aws/secretsmanager" {
		configured = ""
	}
	key, err := s.encryptionKey(ctx, configured)
	if err != nil {
		return err
	}
	ec := encryptionContext(target, "RequestToValidateKeyAccess")
	if empty {
		plain, _, _, rejected := s.keys.GenerateDataKey(ctx, key, ec)
		clear(plain)
		if rejected != nil {
			return keyFailure(rejected, false)
		}
	}
	_, _, rejected := s.keys.Encrypt(ctx, key, []byte("RequestToValidateKeyAccess"), ec)
	if rejected != nil {
		return keyFailure(rejected, false)
	}
	return nil
}

type preparedReplicaVersion struct {
	metadata VersionRecord
	value    *SealedValue
}

func (s *Service) prepareReplica(tx Transaction, source SecretRecord, region, keyID string, force bool) error {
	if keyID == "" {
		keyID = "alias/aws/secretsmanager"
	}
	replica := ReplicaRecord{Key: ReplicaKey{Primary: source.Key, Region: region}, PrimaryARN: source.ARN, KMSKeyID: keyID}
	existingLink, err := tx.Replica(replica.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	targetKey := replicaSecretKey(source.Key, region)
	existing, lookupErr := tx.Secret(targetKey)
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return lookupErr
	}
	linked := lookupErr == nil && err == nil && existingLink.PrimaryARN == source.ARN && matchesReplica(existing, existingLink)
	if lookupErr == nil && !linked {
		if !force {
			return s.failReplica(tx, replica, failure("ResourceExistsException", "Secret with this name already exists in this region"))
		}
		if err := checkWritable(tx.Context(), existing); err != nil {
			return s.failReplica(tx, replica, err)
		}
		if err := s.checkPrimaryDeletion(tx, existing); err != nil {
			return s.failReplica(tx, replica, err)
		}
	}
	if err := s.replicaRegionEnabled(tx.Context(), source, region); err != nil {
		return s.failReplica(tx, replica, err)
	}
	target := SecretRecord{Key: targetKey, ARN: regionalSecretARN(source.ARN, region), KMSKeyID: keyID, PrimaryRegion: source.Key.Region, Created: s.clock.Now().UTC()}
	if lookupErr == nil {
		target.Created, target.LastAccessed = existing.Created, existing.LastAccessed
	}
	target = copyReplicaMetadata(target, source)
	versions, err := tx.Versions(source.Key)
	if err != nil {
		return err
	}
	ctx := regionalSecretContext(tx.Context(), region)
	if err := s.validateReplicaKey(ctx, target, len(versions) == 0); err != nil {
		return s.failReplica(tx, replica, err)
	}
	prepared := make([]preparedReplicaVersion, 0, len(versions))
	for _, version := range versions {
		keys, err := tx.VersionKeyIDs(version.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		metadata := version
		metadata.Key.Secret, metadata.LastAccessed = target.Key, nil
		if linked {
			old, err := tx.Version(metadata.Key)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil {
				metadata.LastAccessed = old.LastAccessed
			}
		}
		item := preparedReplicaVersion{metadata: metadata}
		if len(keys) != 0 {
			plain, err := s.openVersion(tx, source, version)
			if err != nil {
				return s.failReplica(tx, replica, err)
			}
			sealed, err := s.sealVersion(ctx, target, version.Key.ID, plain)
			clear(plain)
			if err != nil {
				return s.failReplica(tx, replica, err)
			}
			item.value = &sealed
		}
		prepared = append(prepared, item)
	}
	// Do not replace a colliding secret or expose a partial destination if any
	// source decryption or destination encryption failed above.
	if lookupErr == nil {
		if err := tx.DeleteSecret(existing.Key); err != nil {
			return err
		}
	}
	if err := tx.PutSecret(target); err != nil {
		return err
	}
	for _, item := range prepared {
		if err := tx.PutVersion(item.metadata); err != nil {
			return err
		}
		if item.value != nil {
			if err := tx.PutEncryptedVersion(item.metadata.Key, []SealedValue{*item.value}); err != nil {
				return err
			}
		}
	}
	return s.queueReplica(tx, replica)
}

// Replica propagation reads the stored version through source KMS authority.
// Failure belongs to the replica; it must not reject the successful primary Put.
func (s *Service) replicateVersion(tx Transaction, source SecretRecord, version VersionRecord) error {
	current, err := tx.Secret(source.Key)
	if err != nil {
		return err
	}
	if current.ARN != source.ARN {
		return nil
	}
	replicas, err := tx.Replicas(source.Key)
	if err != nil {
		return err
	}
	replicas = slices.DeleteFunc(replicas, func(replica ReplicaRecord) bool {
		return replica.PrimaryARN != source.ARN || replica.Status == "Failed"
	})
	if len(replicas) == 0 {
		return nil
	}
	plaintext, sourceError := s.openVersion(tx, source, version)
	defer clear(plaintext)
	for _, replica := range replicas {
		if sourceError != nil {
			if err := s.failReplica(tx, replica, sourceError); err != nil {
				return err
			}
			continue
		}
		target, err := tx.Secret(replicaSecretKey(source.Key, replica.Key.Region))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err != nil || !matchesReplica(target, replica) {
			if err := s.failReplica(tx, replica, failure("ResourceNotFoundException", "The replica secret no longer exists.")); err != nil {
				return err
			}
			continue
		}
		ctx := regionalSecretContext(tx.Context(), target.Key.Region)
		if err := s.validateReplicaKey(ctx, target, false); err != nil {
			if err := s.failReplica(tx, replica, err); err != nil {
				return err
			}
			continue
		}
		sealed, err := s.sealVersion(ctx, target, version.Key.ID, plaintext)
		if err != nil {
			if err := s.failReplica(tx, replica, err); err != nil {
				return err
			}
			continue
		}
		metadata := version
		metadata.Key.Secret, metadata.LastAccessed = target.Key, nil
		if err := tx.PutVersion(metadata); err != nil {
			return err
		}
		if err := tx.PutEncryptedVersion(metadata.Key, []SealedValue{sealed}); err != nil {
			return err
		}
	}
	return nil
}

// refreshReplicas synchronizes metadata and labels without reading encrypted
// payloads. In particular, a label-only change never copies stale secret bytes.
func (s *Service) refreshReplicas(tx Transaction, source SecretRecord) error {
	current, err := tx.Secret(source.Key)
	if err != nil {
		return err
	}
	if current.ARN != source.ARN {
		return nil
	}
	source = current
	replicas, err := tx.Replicas(source.Key)
	if err != nil {
		return err
	}
	if len(replicas) == 0 {
		return nil
	}
	versions, err := tx.Versions(source.Key)
	if err != nil {
		return err
	}
	for _, replica := range replicas {
		if replica.PrimaryARN != source.ARN || replica.Status == "Failed" {
			continue
		}
		target, err := tx.Secret(replicaSecretKey(source.Key, replica.Key.Region))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err != nil || !matchesReplica(target, replica) {
			if err := s.failReplica(tx, replica, failure("ResourceNotFoundException", "The replica secret no longer exists.")); err != nil {
				return err
			}
			continue
		}
		oldVersions, err := tx.Versions(target.Key)
		if err != nil {
			return err
		}
		byID := make(map[string]VersionRecord, len(oldVersions))
		for _, version := range oldVersions {
			byID[version.Key.ID] = version
		}
		missingValue := false
		for _, version := range versions {
			if _, exists := byID[version.Key.ID]; exists {
				continue
			}
			keys, err := tx.VersionKeyIDs(version.Key)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if len(keys) != 0 {
				missingValue = true
				break
			}
		}
		if missingValue {
			if err := s.failReplica(tx, replica, failure("InvalidRequestException", "A secret version is missing in the replica. Retry replication to synchronize its value.")); err != nil {
				return err
			}
			continue
		}
		for _, version := range versions {
			metadata := version
			metadata.Key.Secret = target.Key
			metadata.LastAccessed = byID[version.Key.ID].LastAccessed
			if err := tx.PutVersion(metadata); err != nil {
				return err
			}
			delete(byID, version.Key.ID)
		}
		for _, version := range oldVersions {
			if _, obsolete := byID[version.Key.ID]; obsolete {
				if err := tx.DeleteVersion(version.Key); err != nil {
					return err
				}
			}
		}
		if err := tx.PutSecret(copyReplicaMetadata(target, source)); err != nil {
			return err
		}
		if err := s.queueReplica(tx, replica); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) removeRegionsFromReplication(tx Transaction, in *api.RemoveRegionsFromReplicationInput) (*api.RemoveRegionsFromReplicationOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(tx, "RemoveRegionsFromReplication", secret, nil); err != nil {
		return nil, err
	}
	if err := checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	if len(in.RemoveReplicaRegions) == 0 {
		return nil, failure("InvalidParameterException", "RemoveReplicaRegions must contain at least one region.")
	}
	for _, region := range in.RemoveReplicaRegions {
		if err := validateReplicaRegion(secret, string(region)); err != nil {
			return nil, err
		}
	}
	for _, region := range in.RemoveReplicaRegions {
		replica, err := tx.Replica(ReplicaKey{Primary: secret.Key, Region: string(region)})
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if replica.PrimaryARN != secret.ARN {
			continue
		}
		target, err := tx.Secret(replicaSecretKey(secret.Key, string(region)))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err == nil && matchesReplica(target, replica) {
			if err := tx.DeleteSecret(target.Key); err != nil {
				return nil, err
			}
		}
		if err := tx.DeleteReplica(replica.Key); err != nil {
			return nil, err
		}
	}
	if err := clearPrimaryRegion(tx, secret); err != nil {
		return nil, err
	}
	statuses, err := s.replicationStatus(tx, secret)
	if err != nil {
		return nil, err
	}
	return &api.RemoveRegionsFromReplicationOutput{ARN: str[api.SecretARNType](secret.ARN), ReplicationStatus: statuses}, nil
}

func clearPrimaryRegion(tx Transaction, secret SecretRecord) error {
	replicas, err := tx.Replicas(secret.Key)
	if err != nil {
		return err
	}
	for _, replica := range replicas {
		if replica.PrimaryARN == secret.ARN {
			return nil
		}
	}
	secret.PrimaryRegion = ""
	return tx.PutSecret(secret)
}

func (s *Service) stopReplicationToReplica(tx Transaction, in *api.StopReplicationToReplicaInput) (*api.StopReplicationToReplicaOutput, error) {
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(tx, "StopReplicationToReplica", secret, nil); err != nil {
		return nil, err
	}
	if err := checkNotDeleted(secret); err != nil {
		return nil, err
	}
	if secret.PrimaryRegion == "" || secret.PrimaryRegion == secret.Key.Region {
		return nil, failure("InvalidParameterException", "Operation not permitted on a primary secret. Call must be made in replica secret's region.")
	}
	primaryKey := replicaSecretKey(secret.Key, secret.PrimaryRegion)
	primaryARN := regionalSecretARN(secret.ARN, secret.PrimaryRegion)
	replicaKey := ReplicaKey{Primary: primaryKey, Region: secret.Key.Region}
	replica, err := tx.Replica(replicaKey)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil && replica.PrimaryARN == primaryARN {
		if err := tx.DeleteReplica(replicaKey); err != nil {
			return nil, err
		}
	}
	primary, err := tx.Secret(primaryKey)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil && primary.ARN == primaryARN {
		if err := clearPrimaryRegion(tx, primary); err != nil {
			return nil, err
		}
	}
	secret.PrimaryRegion, secret.Changed = "", s.clock.Now().UTC()
	if err := tx.PutSecret(secret); err != nil {
		return nil, err
	}
	return &api.StopReplicationToReplicaOutput{ARN: str[api.SecretARNType](secret.ARN)}, nil
}
