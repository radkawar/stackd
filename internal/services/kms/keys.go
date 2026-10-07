package kms

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func (s *Service) registerKeys() {
	register(s, "CreateKey", s.createKey)
	register(s, "DescribeKey", s.describeKey)
	register(s, "ListKeys", s.listKeys)
	register(s, "EnableKey", func(ctx context.Context, in *kmsapi.EnableKeyInput) (*kmsapi.EnableKeyOutput, *awswire.Error) {
		if err := s.setState(ctx, value(in.KeyId), "Enabled"); err != nil {
			return nil, err
		}
		return &kmsapi.EnableKeyOutput{}, nil
	})
	register(s, "DisableKey", func(ctx context.Context, in *kmsapi.DisableKeyInput) (*kmsapi.DisableKeyOutput, *awswire.Error) {
		if err := s.setState(ctx, value(in.KeyId), "Disabled"); err != nil {
			return nil, err
		}
		return &kmsapi.DisableKeyOutput{}, nil
	})
	register(s, "UpdateKeyDescription", s.updateDescription)
	register(s, "ScheduleKeyDeletion", s.scheduleDeletion)
	register(s, "CancelKeyDeletion", s.cancelDeletion)
}

func (s *Service) createKey(ctx context.Context, in *kmsapi.CreateKeyInput) (*kmsapi.CreateKeyOutput, *awswire.Error) {
	owner, ownerErr := keyResourceOwnerFor(ctx)
	if ownerErr != nil {
		return nil, ownerErr
	}
	origin := value(in.Origin)
	if origin == "" {
		origin = "AWS_KMS"
	}
	if origin != "AWS_KMS" && origin != "EXTERNAL" || in.CustomKeyStoreId != nil || in.XksKeyId != nil {
		return nil, failure("UnsupportedOperationException", "Only AWS_KMS and EXTERNAL key origins are implemented.")
	}
	spec := value(in.KeySpec)
	if in.CustomerMasterKeySpec != nil {
		if spec != "" && spec != value(in.CustomerMasterKeySpec) {
			return nil, failure("ValidationException", "KeySpec and CustomerMasterKeySpec must agree.")
		}
		spec = value(in.CustomerMasterKeySpec)
	}
	if spec == "" {
		spec = "SYMMETRIC_DEFAULT"
	}
	_, hash := hmacSpec(spec)
	if spec != "SYMMETRIC_DEFAULT" && hash == 0 && !asymmetricSpec(spec) {
		return nil, failure("UnsupportedOperationException", "This key specification is not implemented.")
	}
	if origin == "EXTERNAL" && mldsaSpec(spec) {
		return nil, failure("ValidationException", "EXTERNAL origin is not supported for ML-DSA keys.")
	}
	usage := value(in.KeyUsage)
	if usage == "" {
		if spec != "SYMMETRIC_DEFAULT" {
			return nil, failure("ValidationException", "You must specify a KeyUsage value for all KMS keys except for symmetric encryption keys.")
		}
		usage = "ENCRYPT_DECRYPT"
	}
	if hash != 0 && usage != "GENERATE_VERIFY_MAC" {
		return nil, failure("ValidationException", fmt.Sprintf("KeyUsage %s is not compatible with KeySpec %s", usage, spec))
	}
	if rsaBits(spec) != 0 && usage != "ENCRYPT_DECRYPT" && usage != "SIGN_VERIFY" {
		return nil, failure("ValidationException", fmt.Sprintf("KeyUsage %s is not compatible with KeySpec %s", usage, spec))
	}
	if asymmetricSpec(spec) && rsaBits(spec) == 0 && usage != "SIGN_VERIFY" && !(keyAgreementSpec(spec) && usage == "KEY_AGREEMENT") {
		return nil, failure("ValidationException", fmt.Sprintf("KeyUsage %s is not compatible with KeySpec %s", usage, spec))
	}
	if spec == "SYMMETRIC_DEFAULT" && usage != "ENCRYPT_DECRYPT" {
		return nil, failure("InvalidKeyUsageException", "SYMMETRIC_DEFAULT keys require ENCRYPT_DECRYPT usage.")
	}
	if spec == "SYMMETRIC_DEFAULT" && scopeFor(ctx).partition == "aws-cn" {
		// TODO: Comeback implement SM4-backed SYMMETRIC_DEFAULT keys for China regions.
		return nil, failure("UnsupportedOperationException", "SM4 keys for China regions are not implemented.")
	}
	tags, err := mergeTags(nil, in.Tags)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeKeyCreation(ctx, spec, usage, origin, isTrue(in.MultiRegion), isTrue(in.BypassPolicyLockoutSafetyCheck), in.Tags); err != nil {
		return nil, err
	}
	bound, err := s.creationPolicy(ctx, in.Policy, "*", isTrue(in.BypassPolicyLockoutSafetyCheck))
	if err != nil {
		return nil, err
	}
	if isTrue(in.MultiRegion) {
		if err := s.ensureMultiRegionRole(ctx); err != nil {
			return nil, err
		}
	}
	if owner != (KeyResourceOwner{}) {
		for _, existing := range s.store(ctx).keys {
			if existing.owner == owner {
				return &kmsapi.CreateKeyOutput{KeyMetadata: metadata(ctx, existing)}, nil
			}
		}
	}
	k, err := s.newKey(ctx, value(in.Description), "CUSTOMER", KeySetRecord{Spec: spec, Usage: usage, Origin: origin, MultiRegion: isTrue(in.MultiRegion)}, tags)
	if err != nil {
		return nil, err
	}
	k.policy, k.principalIDs = bound.Document, bound.PrincipalIDs
	k.owner = owner
	return &kmsapi.CreateKeyOutput{KeyMetadata: metadata(ctx, k)}, nil
}

func (s *Service) describeKey(ctx context.Context, in *kmsapi.DescribeKeyInput) (*kmsapi.DescribeKeyOutput, *awswire.Error) {
	ctx = withGrantTokens(ctx, in.GrantTokens)
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), true)
	if err != nil {
		return nil, err
	}
	return &kmsapi.DescribeKeyOutput{KeyMetadata: metadata(ctx, k)}, nil
}

// DescribeKey resolves a key for an in-process service caller with the same
// authorization and transactional audit behavior as the public operation.
func (s *Service) DescribeKey(ctx context.Context, keyID string) (*kmsapi.KeyMetadata, *awswire.Error) {
	input := &kmsapi.DescribeKeyInput{KeyId: ptr(kmsapi.KeyIdType(keyID))}
	output, err := s.auditCommand(ctx, "DescribeKey", input, func(ctx context.Context) (any, *awswire.Error) {
		return s.describeKey(ctx, input)
	})
	if err != nil {
		return nil, err
	}
	return output.(*kmsapi.DescribeKeyOutput).KeyMetadata, nil
}

func (s *Service) listKeys(ctx context.Context, in *kmsapi.ListKeysInput) (*kmsapi.ListKeysOutput, *awswire.Error) {
	st := s.store(ctx)
	ids := make([]string, 0, len(st.keys))
	for id := range st.keys {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	page, next, err := s.page(ctx, "ListKeys", "", ids, in.Limit, in.Marker)
	if err != nil {
		return nil, err
	}
	out := &kmsapi.ListKeysOutput{Keys: make(kmsapi.KeyList, 0, len(page)), Truncated: ptr(kmsapi.BooleanType(next != ""))}
	if next != "" {
		out.NextMarker = ptr(kmsapi.MarkerType(next))
	}
	for _, id := range page {
		out.Keys = append(out.Keys, kmsapi.KeyListEntry{KeyId: ptr(kmsapi.KeyIdType(id)), KeyArn: ptr(kmsapi.ArnType(st.keys[id].arn))})
	}
	return out, nil
}

func (s *Service) setState(ctx context.Context, keyID, state string) *awswire.Error {
	k, err := s.resolveAuthorized(ctx, keyID, false)
	if err != nil {
		return err
	}
	if err := customerKey(k); err != nil {
		return err
	}
	if k.state != "Enabled" && k.state != "Disabled" {
		return failure("KMSInvalidStateException", "The key state cannot be changed until deletion is canceled.")
	}
	wasDisabled := k.state == "Disabled"
	k.state = state
	if wasDisabled && state == "Enabled" && k.PrimaryRegion == keyScope(k).region {
		resumeRotation(k, s.currentTime())
	}
	return nil
}

func (s *Service) updateDescription(ctx context.Context, in *kmsapi.UpdateKeyDescriptionInput) (*kmsapi.UpdateKeyDescriptionOutput, *awswire.Error) {
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	if err := customerKey(k); err != nil {
		return nil, err
	}
	if k.state == "PendingDeletion" || k.state == "PendingReplicaDeletion" {
		return nil, failure("KMSInvalidStateException", "The key is pending deletion.")
	}
	k.description = value(in.Description)
	return &kmsapi.UpdateKeyDescriptionOutput{}, nil
}

func (s *Service) scheduleDeletion(ctx context.Context, in *kmsapi.ScheduleKeyDeletionInput) (*kmsapi.ScheduleKeyDeletionOutput, *awswire.Error) {
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	if err := customerKey(k); err != nil {
		return nil, err
	}
	if k.state != "Enabled" && k.state != "Disabled" && k.state != "Creating" && k.state != "PendingImport" {
		return nil, failure("KMSInvalidStateException", "The key is already pending deletion.")
	}
	days := kmsapi.PendingWindowInDaysType(30)
	if in.PendingWindowInDays != nil {
		days = *in.PendingWindowInDays
	}
	if days < 7 || days > 30 {
		return nil, failure("ValidationException", "PendingWindowInDays must be between 7 and 30.")
	}
	deletion := s.currentTime().UTC().Add(time.Duration(days) * 24 * time.Hour)
	k.state, k.deletion, k.availableAt = "PendingDeletion", &deletion, time.Time{}
	if k.MultiRegion && k.PrimaryRegion == keyScope(k).region && len(k.ReplicaRegions) > 0 {
		k.state, k.deletion, k.pendingDeletionWindowInDays = "PendingReplicaDeletion", nil, int32(days)
	}
	return &kmsapi.ScheduleKeyDeletionOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn)), KeyState: ptr(kmsapi.KeyState(k.state)), DeletionDate: k.deletion, PendingWindowInDays: ptr(days)}, nil
}

func (s *Service) cancelDeletion(ctx context.Context, in *kmsapi.CancelKeyDeletionInput) (*kmsapi.CancelKeyDeletionOutput, *awswire.Error) {
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	if err := customerKey(k); err != nil {
		return nil, err
	}
	if k.state != "PendingDeletion" && k.state != "PendingReplicaDeletion" {
		return nil, failure("KMSInvalidStateException", "The key is not pending deletion.")
	}
	k.state, k.deletion, k.pendingDeletionWindowInDays = "Disabled", nil, 0
	if k.Origin == "EXTERNAL" && !allImported(k) {
		k.state = "PendingImport"
	}
	return &kmsapi.CancelKeyDeletionOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn))}, nil
}

// authorizeKeyCreation is shared by primary creation and destination replication.
func (s *Service) authorizeKeyCreation(ctx context.Context, spec, usage, origin string, multiRegion, bypass bool, tags kmsapi.TagList) *awswire.Error {
	conditions := tagConditions(tags)
	conditions["kms:KeySpec"], conditions["kms:KeyUsage"], conditions["kms:KeyOrigin"], conditions["kms:MultiRegion"] = []string{spec}, []string{usage}, []string{origin}, []string{strconv.FormatBool(multiRegion)}
	conditions["kms:BypassPolicyLockoutSafetyCheck"] = []string{strconv.FormatBool(bypass)}
	if err := s.authorize(withAction(ctx, "CreateKey", nil), "*", "", false, conditions); err != nil {
		return err
	}
	if len(tags) > 0 {
		return s.authorize(withAction(ctx, "TagResource", nil), "*", "", false, tagConditions(tags))
	}
	return nil
}

// IsAWSManagedKey exposes immutable key ownership to in-process resource owners.
// It does not invoke DescribeKey, require its IAM permission, or emit a fictitious
// public API call. AWS-managed keys cannot be deleted by account principals.
func (s *Service) IsAWSManagedKey(ctx context.Context, arn string) (bool, error) {
	var managed bool
	err := s.storage.View(ctx, func(r Reader) error {
		keys, err := r.Keys(storageScope(scopeFor(ctx)))
		if err != nil {
			return err
		}
		for _, key := range keys {
			if key.ARN == arn {
				managed = key.Manager == "AWS"
				break
			}
		}
		return nil
	})
	return managed, err
}
