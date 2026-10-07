package kms

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"time"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// RegionAccess supplies the account's current destination-Region opt-in state.
type RegionAccess interface {
	RegionEnabled(context.Context, string, string, time.Time) (bool, error)
}

func (s *Service) registerMultiRegion() {
	register(s, "ReplicateKey", s.replicateKey)
	register(s, "UpdatePrimaryRegion", s.updatePrimaryRegion)
}

func multiRegionMetadata(k *key) *kmsapi.MultiRegionConfiguration {
	sc := keyScope(k)
	kind := kmsapi.MultiRegionKeyTypeREPLICA
	if sc.region == k.PrimaryRegion {
		kind = kmsapi.MultiRegionKeyTypePRIMARY
	}
	entry := func(region string) kmsapi.MultiRegionKey {
		sc.region = region
		return kmsapi.MultiRegionKey{Arn: ptr(kmsapi.ArnType(sc.arn("key/" + k.ID))), Region: ptr(kmsapi.RegionType(region))}
	}
	result := &kmsapi.MultiRegionConfiguration{MultiRegionKeyType: &kind, PrimaryKey: ptr(entry(k.PrimaryRegion)), ReplicaKeys: make(kmsapi.MultiRegionKeyList, 0, len(k.ReplicaRegions))}
	for _, region := range k.ReplicaRegions {
		result.ReplicaKeys = append(result.ReplicaKeys, entry(region))
	}
	return result
}

func regionalContext(ctx context.Context, region string) context.Context {
	m := awsctx.FromContext(ctx)
	m.Region = region
	return awsctx.WithMetadata(ctx, m)
}

func (s *Service) replicaRegion(ctx context.Context, region string) *awswire.Error {
	// TODO: Comeback capture noncommercial multi-Region availability/service-role templates and remaining regional permission, quota and propagation conformance.
	// The commercial catalogue is generated from AWS DescribeRegions. Other
	// partitions cannot create multi-Region keys without their IAM template.
	if scopeFor(ctx).partition != "aws" || !slices.ContainsFunc(awscatalog.CommercialRegions(), func(r awscatalog.CommercialRegion) bool { return r.Name == region }) {
		return failure("ValidationException", "The replica Region must be a valid Region in the same AWS partition.")
	}
	if s.regions == nil {
		return failure("UnsupportedOperationException", "Multi-Region keys require an Account RegionAccess provider.")
	}
	enabled, err := s.regions.RegionEnabled(ctx, scopeFor(ctx).account, region, s.currentTime())
	if err != nil {
		return failure("KMSInternalException", "Unable to read the account's Region status.")
	}
	if !enabled {
		return failure("ValidationException", "The replica Region is not enabled for this account.")
	}
	return nil
}

func (s *Service) replicateKey(ctx context.Context, in *kmsapi.ReplicateKeyInput) (*kmsapi.ReplicateKeyOutput, *awswire.Error) {
	owner, ownerErr := keyResourceOwnerFor(ctx)
	if ownerErr != nil {
		return nil, ownerErr
	}
	region := value(in.ReplicaRegion)
	ctx = withConditions(ctx, map[string][]string{"kms:ReplicaRegion": {region}, "kms:BypassPolicyLockoutSafetyCheck": {strconv.FormatBool(isTrue(in.BypassPolicyLockoutSafetyCheck))}})
	// The primary is not owned by the replica's stack incarnation. Its current
	// key policy and IAM still authorize ReplicateKey; fence the destination.
	k, err := s.keyIDAuthorized(withoutKeyResourceOwner(ctx), value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if !k.MultiRegion || k.PrimaryRegion != keyScope(k).region {
		return nil, failure("UnsupportedOperationException", "Only a multi-Region primary key can be replicated.")
	}
	if err := usable(k); err != nil {
		return nil, err
	}
	if k.state == "Updating" {
		return nil, failure("KMSInvalidStateException", "The primary Region is being updated.")
	}
	if region == k.PrimaryRegion {
		return nil, failure("ValidationException", "The replica Region must differ from the primary Region.")
	}
	if err := s.replicaRegion(ctx, region); err != nil {
		return nil, err
	}
	destination := regionalContext(ctx, region)
	store := s.store(destination)
	if existing := store.keys[k.ID]; existing != nil {
		if owner == (KeyResourceOwner{}) || existing.owner != owner {
			return nil, failure("AlreadyExistsException", "A related key already exists in the replica Region.")
		}
		if err := s.authorizeKeyCreation(destination, k.Spec, k.Usage, k.Origin, true, isTrue(in.BypassPolicyLockoutSafetyCheck), in.Tags); err != nil {
			return nil, err
		}
		return replicaResult(destination, existing), nil
	}
	if owner != (KeyResourceOwner{}) {
		for _, existing := range store.keys {
			if existing.owner == owner {
				return nil, failure("AlreadyExistsException", "The resource incarnation already owns a replica of another primary key.")
			}
		}
	}
	tags, err := mergeTags(nil, in.Tags)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeKeyCreation(destination, k.Spec, k.Usage, k.Origin, true, isTrue(in.BypassPolicyLockoutSafetyCheck), in.Tags); err != nil {
		return nil, err
	}
	arn := scopeFor(destination).arn("key/" + k.ID)
	bound, err := s.creationPolicy(destination, in.Policy, arn, isTrue(in.BypassPolicyLockoutSafetyCheck))
	if err != nil {
		return nil, err
	}
	now := s.currentTime().UTC()
	replica := &key{KeySetRecord: k.KeySetRecord, arn: arn, description: value(in.Description), manager: "CUSTOMER", state: "Creating", created: now, availableAt: now.Add(replicaCreationDelay), policy: bound.Document, principalIDs: bound.PrincipalIDs, tags: tags, imports: make(map[string]ImportedMaterialRecord)}
	replica.owner = owner
	store.keys[k.ID] = replica
	k.ReplicaRegions = append(k.ReplicaRegions, region)
	slices.Sort(k.ReplicaRegions)
	if audit, _ := ctx.Value(auditContextKey{}).(*auditContext); audit != nil && s.apiEvents != nil {
		audit.regional = append(audit.regional, regionalAudit{
			region: region, name: "CreateKey",
			input:    &kmsapi.CreateKeyInput{Description: in.Description, Policy: in.Policy, Tags: in.Tags, KeySpec: ptr(kmsapi.KeySpec(k.Spec)), KeyUsage: ptr(kmsapi.KeyUsageType(k.Usage)), Origin: ptr(kmsapi.OriginType(k.Origin)), MultiRegion: ptr(kmsapi.NullableBooleanType(true)), BypassPolicyLockoutSafetyCheck: in.BypassPolicyLockoutSafetyCheck},
			output:   &kmsapi.CreateKeyOutput{KeyMetadata: metadata(destination, replica)},
			resource: journal.APIEventResource{AccountID: keyScope(replica).account, Type: "AWS::KMS::Key", ARN: replica.arn},
		})
	}
	return replicaResult(destination, replica), nil
}

func replicaResult(ctx context.Context, replica *key) *kmsapi.ReplicateKeyOutput {
	tags := make(kmsapi.TagList, 0, len(replica.tags))
	for _, name := range slices.Sorted(maps.Keys(replica.tags)) {
		tags = append(tags, kmsapi.Tag{TagKey: ptr(kmsapi.TagKeyType(name)), TagValue: ptr(kmsapi.TagValueType(replica.tags[name]))})
	}
	return &kmsapi.ReplicateKeyOutput{ReplicaKeyMetadata: metadata(ctx, replica), ReplicaPolicy: ptr(kmsapi.PolicyType(replica.policy)), ReplicaTags: tags}
}

func (s *Service) updatePrimaryRegion(ctx context.Context, in *kmsapi.UpdatePrimaryRegionInput) (*kmsapi.UpdatePrimaryRegionOutput, *awswire.Error) {
	region := value(in.PrimaryRegion)
	ctx = withConditions(ctx, map[string][]string{"kms:PrimaryRegion": {region}})
	k, err := s.keyIDAuthorized(ctx, value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if !k.MultiRegion {
		return nil, failure("UnsupportedOperationException", "The key must be a multi-Region primary key.")
	}
	if k.PrimaryRegion != keyScope(k).region {
		return nil, failure("KMSInvalidStateException", "The key must be an enabled multi-Region primary key.")
	}
	if err := usable(k); err != nil {
		return nil, err
	}
	if k.state == "Updating" {
		return nil, failure("KMSInvalidStateException", "The primary Region is being updated.")
	}
	if region == k.PrimaryRegion {
		return &kmsapi.UpdatePrimaryRegionOutput{}, nil
	}
	if !slices.Contains(k.ReplicaRegions, region) {
		return nil, failure("ValidationException", "A related replica key must already exist in the new primary Region.")
	}
	destination := regionalContext(ctx, region)
	replica, err := s.resolveAuthorized(destination, k.ID, false)
	if err != nil {
		return nil, err
	}
	if err := usable(replica); err != nil {
		return nil, err
	}
	if replica.state == "Updating" {
		return nil, failure("KMSInvalidStateException", "The new primary key must be enabled.")
	}
	for i, candidate := range k.ReplicaRegions {
		if candidate == region {
			k.ReplicaRegions[i] = k.PrimaryRegion
		}
	}
	slices.Sort(k.ReplicaRegions)
	k.PrimaryRegion = region
	k.state, replica.state = "Updating", "Updating"
	k.availableAt = s.currentTime().Add(primaryUpdateDelay)
	if audit, _ := ctx.Value(auditContextKey{}).(*auditContext); audit != nil && s.apiEvents != nil {
		audit.regional = append(audit.regional, regionalAudit{
			region: region, name: "UpdatePrimaryRegion",
			input:    &kmsapi.UpdatePrimaryRegionInput{KeyId: ptr(kmsapi.KeyIdType(replica.arn)), PrimaryRegion: in.PrimaryRegion},
			output:   &kmsapi.UpdatePrimaryRegionOutput{},
			resource: journal.APIEventResource{AccountID: keyScope(replica).account, Type: "AWS::KMS::Key", ARN: replica.arn},
		})
	}
	replica.availableAt = k.availableAt
	return &kmsapi.UpdatePrimaryRegionOutput{}, nil
}
