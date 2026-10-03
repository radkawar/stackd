package kms

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func (s *Service) registerRotation() {
	register(s, "EnableKeyRotation", s.enableKeyRotation)
	register(s, "DisableKeyRotation", s.disableKeyRotation)
	register(s, "GetKeyRotationStatus", s.getKeyRotationStatus)
	register(s, "RotateKeyOnDemand", s.rotateKeyOnDemand)
	register(s, "ListKeyRotations", s.listKeyRotations)
}

func (s *Service) keyIDAuthorized(ctx context.Context, id string) (*key, *awswire.Error) {
	if strings.HasPrefix(id, "alias/") || strings.Contains(id, ":alias/") {
		return nil, failure("InvalidArnException", "Key Aliases are not supported for this operation.")
	}
	return s.resolveAuthorized(ctx, id, false)
}

func rotationWritable(k *key) *awswire.Error {
	if err := customerKey(k); err != nil {
		return err
	}
	if k.MultiRegion && keyScope(k).region != k.PrimaryRegion {
		return failure("UnsupportedOperationException", "Rotation can only be changed on a multi-Region primary key.")
	}
	if k.state == "Disabled" {
		return failure("DisabledException", k.arn+" is disabled.")
	}
	if k.state != "Enabled" && k.state != "Updating" {
		return failure("KMSInvalidStateException", k.arn+" is pending deletion.")
	}
	return nil
}

func (s *Service) enableKeyRotation(ctx context.Context, in *kmsapi.EnableKeyRotationInput) (*kmsapi.EnableKeyRotationOutput, *awswire.Error) {
	period := int32(365)
	if in.RotationPeriodInDays != nil {
		period = int32(*in.RotationPeriodInDays)
	}
	// AWS authorizes the default 365 even when an omitted parameter will leave
	// an already enabled key's shorter rotation period unchanged.
	ctx = withConditions(ctx, map[string][]string{"kms:RotationPeriodInDays": {strconv.Itoa(int(period))}})
	k, err := s.keyIDAuthorized(ctx, value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if k.Origin == "EXTERNAL" {
		return nil, failure("UnsupportedOperationException", "Automatic rotation is not supported for imported material.")
	}
	if err := rotationWritable(k); err != nil {
		return nil, err
	}
	if k.Spec != "SYMMETRIC_DEFAULT" {
		return nil, failure("UnsupportedOperationException", "")
	}
	if in.RotationPeriodInDays == nil && k.Rotation.Enabled {
		period = k.Rotation.PeriodInDays
	}
	if !k.Rotation.Enabled || k.Rotation.PeriodInDays != period {
		k.Rotation.Enabled, k.Rotation.PeriodInDays = true, period
		k.Rotation.Next = s.currentTime().UTC().Add(time.Duration(period) * 24 * time.Hour)
	}
	return &kmsapi.EnableKeyRotationOutput{}, nil
}

func (s *Service) disableKeyRotation(ctx context.Context, in *kmsapi.DisableKeyRotationInput) (*kmsapi.DisableKeyRotationOutput, *awswire.Error) {
	k, err := s.keyIDAuthorized(ctx, value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if k.Origin == "EXTERNAL" {
		return nil, failure("UnsupportedOperationException", "Automatic rotation is not supported for imported material.")
	}
	if err := rotationWritable(k); err != nil {
		return nil, err
	}
	k.Rotation.Enabled = false
	k.Rotation.Next = time.Time{}
	return &kmsapi.DisableKeyRotationOutput{}, nil
}

func (s *Service) getKeyRotationStatus(ctx context.Context, in *kmsapi.GetKeyRotationStatusInput) (*kmsapi.GetKeyRotationStatusOutput, *awswire.Error) {
	k, err := s.keyIDAuthorized(ctx, value(in.KeyId))
	if err != nil {
		return nil, err
	}
	// TODO: Comeback verify rotation-status transitions for aged AWS-managed keys; fresh SQS captures report false despite documentation saying always enabled.
	enabled := k.Rotation.Enabled && k.state != "PendingDeletion"
	out := &kmsapi.GetKeyRotationStatusOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn)), KeyRotationEnabled: ptr(kmsapi.BooleanType(enabled))}
	if enabled {
		out.RotationPeriodInDays = ptr(kmsapi.RotationPeriodInDaysType(k.Rotation.PeriodInDays))
		out.NextRotationDate = ptr(k.Rotation.Next)
	}
	if !k.Rotation.OnDemandStarted.IsZero() {
		out.OnDemandRotationStartDate = ptr(k.Rotation.OnDemandStarted)
	}
	return out, nil
}

func (s *Service) rotateKeyOnDemand(ctx context.Context, in *kmsapi.RotateKeyOnDemandInput) (*kmsapi.RotateKeyOnDemandOutput, *awswire.Error) {
	k, err := s.keyIDAuthorized(ctx, value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if err := rotationWritable(k); err != nil {
		return nil, err
	}
	if k.Spec != "SYMMETRIC_DEFAULT" {
		return nil, failure("UnsupportedOperationException", "")
	}
	if k.Origin == "EXTERNAL" && !s.pendingImportReady(k) {
		return nil, failure("KMSInvalidStateException", "No key material is ready for rotation in all related Regions.")
	}
	if k.Rotation.OnDemandStarted.IsZero() {
		rotations := 0
		for _, material := range k.Materials {
			if material.RotationType == "ON_DEMAND" {
				rotations++
			}
		}
		if rotations >= 25 {
			return nil, failure("LimitExceededException", "The key has reached its on-demand rotation limit.")
		}
		now := s.currentTime().UTC()
		if k.Rotation.Enabled && !k.Rotation.Next.After(now.Add(20*time.Minute)) {
			return nil, failure("ConflictException", "An automatic rotation is scheduled to begin within the next 20 minutes.")
		}
		k.Rotation.OnDemandStarted = now
	}
	return &kmsapi.RotateKeyOnDemandOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn))}, nil
}

func (s *Service) listKeyRotations(ctx context.Context, in *kmsapi.ListKeyRotationsInput) (*kmsapi.ListKeyRotationsOutput, *awswire.Error) {
	k, err := s.keyIDAuthorized(ctx, value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if k.Spec != "SYMMETRIC_DEFAULT" && in.IncludeKeyMaterial != nil {
		return nil, failure("ValidationException", "IncludeKeyMaterial can only be used with symmetric keys.")
	}
	includeAll := value(in.IncludeKeyMaterial) == "ALL_KEY_MATERIAL"
	items := make([]string, 0, len(k.Materials))
	for i, material := range k.Materials {
		if k.Spec == "SYMMETRIC_DEFAULT" && material.ID != "" && (includeAll || !material.RotationDate.IsZero()) {
			items = append(items, fmt.Sprintf("%020d", i))
		}
	}
	page, next, err := s.page(ctx, "ListKeyRotations", k.arn, items, in.Limit, in.Marker)
	if err != nil {
		if err.Code == "InvalidMarkerException" {
			err.Message = ""
		}
		return nil, err
	}
	out := &kmsapi.ListKeyRotationsOutput{Rotations: make(kmsapi.RotationsList, 0, len(page)), Truncated: ptr(kmsapi.BooleanType(next != ""))}
	if next != "" {
		out.NextMarker = ptr(kmsapi.MarkerType(next))
	}
	for _, item := range page {
		i, _ := strconv.Atoi(item)
		material := &k.Materials[i]
		state := kmsapi.KeyMaterialState("NON_CURRENT")
		if material.ID == k.CurrentMaterialID {
			state = "CURRENT"
		}
		if material.ID == k.PendingMaterialID {
			state = "PENDING_ROTATION"
			if !s.pendingImportReady(k) {
				state = "PENDING_MULTI_REGION_IMPORT_AND_ROTATION"
			}
		}
		entry := kmsapi.RotationsListEntry{KeyId: ptr(kmsapi.KeyIdType(k.arn)), KeyMaterialId: keyMaterialID(k, material), KeyMaterialState: &state}
		if !material.RotationDate.IsZero() {
			entry.RotationDate, entry.RotationType = ptr(material.RotationDate), ptr(kmsapi.RotationType(material.RotationType))
		}
		if k.Origin == "EXTERNAL" {
			entry.ImportState = ptr(kmsapi.ImportState("PENDING_IMPORT"))
			if material.Description != "" {
				entry.KeyMaterialDescription = ptr(kmsapi.KeyMaterialDescriptionType(material.Description))
			}
			if imported, present := k.imports[material.ID]; present {
				entry.ImportState = ptr(kmsapi.ImportState("IMPORTED"))
				entry.ExpirationModel = ptr(importExpiration(imported))
				entry.ValidTo = imported.ValidTo
			}
		}
		out.Rotations = append(out.Rotations, entry)
	}
	return out, nil
}
