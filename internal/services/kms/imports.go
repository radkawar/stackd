package kms

import (
	"context"
	"time"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func (s *Service) importKeyMaterial(ctx context.Context, in *kmsapi.ImportKeyMaterialInput) (*kmsapi.ImportKeyMaterialOutput, *awswire.Error) {
	model := value(in.ExpirationModel)
	if model == "" {
		model = "KEY_MATERIAL_EXPIRES"
	}
	conditions := map[string][]string{"kms:ExpirationModel": {model}}
	if in.ValidTo != nil {
		conditions["kms:ValidTo"] = []string{in.ValidTo.UTC().Format(time.RFC3339Nano)}
	}
	k, err := s.keyIDAuthorized(withConditions(ctx, conditions), value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if err := importable(k); err != nil {
		return nil, err
	}
	if model == "KEY_MATERIAL_EXPIRES" {
		if in.ValidTo == nil || !in.ValidTo.After(s.currentTime()) || in.ValidTo.After(s.currentTime().Add(365*24*time.Hour)) {
			return nil, failure("ValidationException", "ValidTo must be a future date within 365 days.")
		}
	} else if in.ValidTo != nil {
		return nil, failure("ValidationException", "ValidTo must be omitted when key material does not expire.")
	}
	symmetric := k.Spec == "SYMMETRIC_DEFAULT"
	if !symmetric && (in.ImportType != nil || in.KeyMaterialId != nil || in.KeyMaterialDescription != nil) {
		return nil, failure("ValidationException", "ImportType, KeyMaterialId and KeyMaterialDescription are only supported for symmetric keys.")
	}
	primary := keyScope(k).region == k.PrimaryRegion
	if !primary && in.KeyMaterialDescription != nil {
		return nil, failure("ValidationException", "Key material description can only be specified on primary Multi-Region keys.")
	}
	kind := value(in.ImportType)
	if kind == "" {
		kind = "EXISTING_KEY_MATERIAL"
		if len(k.Materials) == 0 {
			kind = "NEW_KEY_MATERIAL"
		}
	}
	if kind == "NEW_KEY_MATERIAL" && (!primary || in.KeyMaterialId != nil) {
		return nil, failure("ValidationException", "New key material requires the primary key and must omit KeyMaterialId.")
	}
	material, err := s.decryptImportedMaterial(k, in.ImportToken, in.EncryptedKeyMaterial)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	id := importedMaterialID(k.ID, material)
	var version *KeyMaterialRecord
	for i := range k.Materials {
		if k.Materials[i].ID == id {
			version = &k.Materials[i]
			break
		}
	}
	if kind == "NEW_KEY_MATERIAL" {
		if version != nil {
			return nil, incorrectImportedMaterial()
		}
		if k.PendingMaterialID != "" {
			return nil, failure("KMSInvalidStateException", "A new key material is already pending rotation.")
		}
		k.Materials = append(k.Materials, KeyMaterialRecord{ID: id})
		version = &k.Materials[len(k.Materials)-1]
		if k.CurrentMaterialID == "" {
			k.CurrentMaterialID = id
		} else {
			k.PendingMaterialID = id
		}
	} else if version == nil || in.KeyMaterialId != nil && value(in.KeyMaterialId) != id {
		return nil, incorrectImportedMaterial()
	}
	version.Material = append(version.Material[:0], material...)
	if in.KeyMaterialDescription != nil {
		version.Description = value(in.KeyMaterialDescription)
	}
	k.imports[id] = ImportedMaterialRecord{ID: id, ValidTo: in.ValidTo}
	if allImported(k) {
		k.state = "Enabled"
	}
	return &kmsapi.ImportKeyMaterialOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn)), KeyMaterialId: keyMaterialID(k, version)}, nil
}

func incorrectImportedMaterial() *awswire.Error {
	return failure("IncorrectKeyMaterialException", "The key material does not match the requested new or previously imported material.")
}

func (s *Service) deleteImportedKeyMaterial(ctx context.Context, in *kmsapi.DeleteImportedKeyMaterialInput) (*kmsapi.DeleteImportedKeyMaterialOutput, *awswire.Error) {
	k, err := s.keyIDAuthorized(ctx, value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if k.Origin != "EXTERNAL" {
		return nil, failure("UnsupportedOperationException", "The key origin must be EXTERNAL.")
	}
	if k.state == "Creating" || k.state == "Updating" {
		return nil, failure("KMSInvalidStateException", "The key is not in a valid state for material deletion.")
	}
	if k.Spec != "SYMMETRIC_DEFAULT" && in.KeyMaterialId != nil {
		return nil, failure("ValidationException", "KeyMaterialId is only supported for symmetric keys.")
	}
	id := k.CurrentMaterialID
	if in.KeyMaterialId != nil {
		id = value(in.KeyMaterialId)
	}
	var version *KeyMaterialRecord
	for i := range k.Materials {
		if k.Materials[i].ID == id {
			version = &k.Materials[i]
			break
		}
	}
	if in.KeyMaterialId != nil && version == nil {
		return nil, failure("ValidationException", "The key material has never been imported into this key.")
	}
	out := &kmsapi.DeleteImportedKeyMaterialOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn))}
	if id := keyMaterialID(k, version); id != nil {
		out.KeyMaterialId = ptr(kmsapi.BackingKeyIdResponseType(*id))
	}
	if version != nil {
		s.removeImportedMaterial(k, version.ID)
	}
	return out, nil
}
