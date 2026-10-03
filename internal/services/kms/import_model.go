package kms

import (
	kmsapi "stackd/internal/awsapi/kms"
	"time"
)

// ImportedMaterialRecord exists while one material version is imported in a
// Region and owns its expiration. KeySetRecord owns its identity and actual bytes.
type ImportedMaterialRecord struct {
	ID      string
	ValidTo *time.Time
}

// ImportParametersRecord binds a wrapping key and token to one regional KMS
// key for 24 hours. Storage protects the private wrapping key like key material.
type ImportParametersRecord struct {
	Token      []byte
	PrivateKey []byte
	Algorithm  string
	ValidTo    time.Time
}

func allImported(k *key) bool {
	if len(k.Materials) == 0 {
		return false
	}
	for _, material := range k.Materials {
		if _, present := k.imports[material.ID]; material.ID != k.PendingMaterialID && !present {
			return false
		}
	}
	return true
}

func importExpiration(imported ImportedMaterialRecord) kmsapi.ExpirationModelType {
	if imported.ValidTo != nil {
		return "KEY_MATERIAL_EXPIRES"
	}
	return "KEY_MATERIAL_DOES_NOT_EXPIRE"
}
