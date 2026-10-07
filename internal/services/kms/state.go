package kms

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// ErrInvalidKeyReference distinguishes an invalid identifier or Region from a
// well-formed reference to an absent key. Both use KMS NotFoundException on wire.
var ErrInvalidKeyReference = errors.New("invalid KMS key reference")

// KeyStateError retains the source key state for services translating a KMS
// failure. KMS's own wire error does not include this internal diagnostic.
type KeyStateError struct {
	State string
}

func (e *KeyStateError) Error() string { return "KMS key state: " + e.State }

func invalidKeyReference(message string) *awswire.Error {
	wire := failure("NotFoundException", message)
	wire.Cause = ErrInvalidKeyReference
	return wire
}

func validKeyID(id string) bool {
	if len(id) != 36 {
		return false
	}
	if strings.HasPrefix(id, "mrk-") {
		return strings.Trim(id[4:], "0123456789abcdef") == ""
	}
	return uuid.Validate(id) == nil
}

type scope struct{ partition, account, region string }
type keyStore struct {
	keys    map[string]*key
	aliases map[string]*alias
}
type key struct {
	*KeySetRecord
	arn, description, manager, state string
	created                          time.Time
	deletion                         *time.Time
	availableAt                      time.Time
	pendingDeletionWindowInDays      int32
	policy                           string
	principalIDs                     map[string]string
	grants                           map[string]*grant
	tags                             map[string]string
	imports                          map[string]ImportedMaterialRecord
	importParameters                 []ImportParametersRecord
	owner                            KeyResourceOwner
}

func (k *key) currentMaterial() *KeyMaterialRecord {
	for i := range k.Materials {
		if k.Materials[i].ID == k.CurrentMaterialID {
			return &k.Materials[i]
		}
	}
	return nil
}

type alias struct {
	name, keyID      string
	created, updated time.Time
	owner            AliasOwner
}

func scopeFor(ctx context.Context) scope {
	m := awsctx.FromContext(ctx)
	return scope{partition: m.Partition, account: m.AccountID, region: m.Region}
}

func (s *Service) store(ctx context.Context) *keyStore {
	return s.scopedStore(scopeFor(ctx))
}

// regionalStore loads state without advancing related regions recursively.
func (s *Service) regionalStore(sc scope) *keyStore {
	st := s.stores[sc]
	if st == nil {
		st = s.loadScope(sc)
		s.stores[sc] = st
	}
	return st
}

func (s *Service) scopedStore(sc scope) *keyStore {
	st := s.regionalStore(sc)
	for _, k := range st.keys {
		s.advanceKeySet(sc.owner(), k.KeySetRecord, s.currentTime())
	}
	return st
}

func (sc scope) owner() KeyOwner {
	return KeyOwner{Partition: sc.partition, AccountID: sc.account}
}

func (sc scope) arn(resource string) string {
	return fmt.Sprintf("arn:%s:kms:%s:%s:%s", sc.partition, sc.region, sc.account, resource)
}

func (s *Service) resolve(ctx context.Context, identifier string, allowAlias bool) (*key, *awswire.Error) {
	st := s.store(ctx)
	resource := identifier
	aliasReference := strings.HasPrefix(resource, "alias/")
	if strings.HasPrefix(identifier, "arn:") {
		parts := strings.SplitN(identifier, ":", 6)
		sc := scopeFor(ctx)
		if len(parts) != 6 || parts[1] != sc.partition || parts[2] != "kms" || parts[3] != sc.region {
			return nil, invalidKeyReference("Key does not exist in this account and region.")
		}
		resource = parts[5]
		aliasReference = strings.HasPrefix(resource, "alias/")
		sc.account = parts[4]
		st = s.scopedStore(sc)
		if !strings.HasPrefix(resource, "key/") && !aliasReference {
			return nil, invalidKeyReference("Invalid key ARN.")
		}
		resource = strings.TrimPrefix(resource, "key/")
	}
	if aliasReference {
		if !allowAlias {
			return nil, invalidKeyReference("A key ID or key ARN is required.")
		}
		a := st.aliases[resource]
		if a == nil {
			return nil, failure("NotFoundException", "Alias does not exist.")
		}
		resource = a.keyID
	} else if !validKeyID(resource) {
		return nil, invalidKeyReference("Invalid key identifier.")
	}
	k := st.keys[resource]
	if k == nil {
		arn := identifier
		if !strings.HasPrefix(arn, "arn:") {
			arn = scopeFor(ctx).arn("key/" + resource)
		}
		return nil, failure("NotFoundException", fmt.Sprintf("Key '%s' does not exist", arn))
	}
	auditKey(ctx, k)
	return k, nil
}

func (s *Service) newKey(ctx context.Context, description, manager string, properties KeySetRecord, tags map[string]string) (*key, *awswire.Error) {
	var id [16]byte
	_, _ = rand.Read(id[:])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	identifier := fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
	if properties.MultiRegion {
		identifier = fmt.Sprintf("mrk-%x", id)
	}
	sc := scopeFor(ctx)
	properties.ID, properties.PrimaryRegion = identifier, sc.region
	if properties.Origin == "AWS_KMS" {
		var material KeyMaterialRecord
		if properties.Spec == "SYMMETRIC_DEFAULT" {
			material = generateSymmetricMaterial()
		} else if asymmetricSpec(properties.Spec) {
			var err *awswire.Error
			material.Material, _, err = generateAsymmetric(properties.Spec)
			if err != nil {
				return nil, err
			}
		} else {
			_, hash := hmacSpec(properties.Spec)
			material.Material = make([]byte, hash.Size())
			_, _ = rand.Read(material.Material)
		}
		properties.Materials = []KeyMaterialRecord{material}
		properties.CurrentMaterialID = material.ID
	}
	set := &properties
	k := &key{KeySetRecord: set, arn: sc.arn("key/" + identifier), description: description, manager: manager, state: "Enabled", created: s.currentTime().UTC(), tags: tags, policy: defaultPolicy(ctx), imports: make(map[string]ImportedMaterialRecord)}
	if properties.Origin == "EXTERNAL" {
		k.state = "PendingImport"
	}
	s.keySets[keySetReference{owner: sc.owner(), id: identifier}] = set
	if manager == "AWS" {
		k.Rotation = RotationState{PeriodInDays: 365, Next: k.created.Add(365 * 24 * time.Hour)}
	}
	s.store(ctx).keys[k.ID] = k
	auditKey(ctx, k)
	return k, nil
}

func keyScope(k *key) scope {
	parts := strings.SplitN(k.arn, ":", 6)
	return scope{partition: parts[1], region: parts[3], account: parts[4]}
}

func metadata(_ context.Context, k *key) *kmsapi.KeyMetadata {
	out := &kmsapi.KeyMetadata{
		AWSAccountId: ptr(kmsapi.AWSAccountIdType(keyScope(k).account)), KeyId: ptr(kmsapi.KeyIdType(k.ID)), Arn: ptr(kmsapi.ArnType(k.arn)),
		CreationDate: ptr(k.created), Description: ptr(kmsapi.DescriptionType(k.description)), Enabled: ptr(kmsapi.BooleanType(k.state == "Enabled")),
		KeyState: ptr(kmsapi.KeyState(k.state)), KeyUsage: ptr(kmsapi.KeyUsageType(k.Usage)), Origin: ptr(kmsapi.OriginType(k.Origin)),
		KeyManager: ptr(kmsapi.KeyManagerType(k.manager)), KeySpec: ptr(kmsapi.KeySpec(k.Spec)), CustomerMasterKeySpec: ptr(kmsapi.CustomerMasterKeySpec(k.Spec)),
		MultiRegion: ptr(kmsapi.NullableBooleanType(k.MultiRegion)), DeletionDate: k.deletion,
	}
	if k.Spec == "SYMMETRIC_DEFAULT" {
		out.EncryptionAlgorithms = kmsapi.EncryptionAlgorithmSpecList{"SYMMETRIC_DEFAULT"}
		if k.state != "Creating" {
			out.CurrentKeyMaterialId = keyMaterialID(k, k.currentMaterial())
		}
	}
	if k.Origin == "EXTERNAL" && k.state != "PendingImport" && k.state != "Creating" {
		if imported, ok := k.imports[k.CurrentMaterialID]; ok {
			out.ExpirationModel = ptr(importExpiration(imported))
			out.ValidTo = imported.ValidTo
		}
	}
	if k.MultiRegion {
		out.MultiRegionConfiguration = multiRegionMetadata(k)
	}
	if k.state == "PendingReplicaDeletion" {
		out.PendingDeletionWindowInDays = ptr(kmsapi.PendingWindowInDaysType(k.pendingDeletionWindowInDays))
	}
	if k.Usage == "GENERATE_VERIFY_MAC" {
		algorithm, _ := hmacSpec(k.Spec)
		out.MacAlgorithms = kmsapi.MacAlgorithmSpecList{algorithm}
	}
	if rsaBits(k.Spec) != 0 && k.Usage == "ENCRYPT_DECRYPT" {
		for _, algorithm := range rsaEncryptionAlgorithms {
			out.EncryptionAlgorithms = append(out.EncryptionAlgorithms, algorithm.name)
		}
	}
	if k.Usage == "SIGN_VERIFY" {
		for _, algorithm := range signingAlgorithms(k.Spec) {
			out.SigningAlgorithms = append(out.SigningAlgorithms, algorithm.name)
		}
	}
	if k.Usage == "KEY_AGREEMENT" {
		out.KeyAgreementAlgorithms = kmsapi.KeyAgreementAlgorithmSpecList{"ECDH"}
	}
	return out
}

func customerKey(k *key) *awswire.Error {
	if k.manager != "CUSTOMER" {
		return failure("AccessDeniedException", "AWS managed keys cannot be modified.")
	}
	return nil
}

func usable(k *key) *awswire.Error {
	if k.state == "Enabled" || k.state == "Updating" {
		return nil
	}
	rejected := failure("KMSInvalidStateException", "The key is not in a valid state for this operation.")
	if k.state == "Disabled" {
		rejected = failure("DisabledException", k.arn+" is disabled.")
	}
	rejected.Cause = &KeyStateError{State: k.state}
	return rejected
}
