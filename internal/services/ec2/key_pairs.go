package ec2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	api "stackd/internal/awsapi/ec2"
)

func registerKeyPairs(s *Service) {
	register(s, "CreateKeyPair", s.createKeyPair)
	register(s, "ImportKeyPair", s.importKeyPair)
	register(s, "DescribeKeyPairs", s.describeKeyPairs)
	register(s, "DeleteKeyPair", s.deleteKeyPair)
}

func validateKeyPairName(name string) error {
	if name == "" {
		return failure("MissingParameter", "The request must contain the parameter KeyName")
	}
	if len(name) > 255 {
		return failure("InvalidParameterValue", "Value for parameter KeyName is invalid. Length exceeds maximum of 255.")
	}
	if strings.TrimSpace(name) != name {
		return failure("InvalidParameterValue", fmt.Sprintf("Invalid value '%s' for keyName. It should be trimmed", name))
	}
	for _, c := range name {
		if c > 127 {
			return failure("InvalidParameterValue", "Value for parameter KeyName is invalid. Character sets beyond ASCII are not supported.")
		}
		if c < 32 || c == 127 {
			return failure("InvalidParameterValue", "Value for parameter KeyName is invalid.")
		}
	}
	return nil
}

func duplicateKeyPair() error {
	return failure("InvalidKeyPair.Duplicate", "The keypair already exists")
}

func admitKeyPairName(ctx context.Context, tx Reader, name string) error {
	if err := validateKeyPairName(name); err != nil {
		return err
	}
	pairs, err := tx.KeyPairs(scopeFor(ctx))
	if err != nil {
		return err
	}
	for _, pair := range pairs {
		if str(pair.Data.KeyName) == name {
			return duplicateKeyPair()
		}
	}
	if len(pairs) >= 5000 {
		return failure("KeyPairLimitExceeded", "The maximum number of key pairs has been reached.")
	}
	return nil
}

func (s *Service) putNewKeyPair(ctx context.Context, tx Transaction, name, kind, public, fingerprint string, tags api.TagList) (KeyPairRecord, error) {
	id, err := tx.NextID(scopeFor(ctx), "key")
	if err != nil {
		return KeyPairRecord{}, err
	}
	if tags == nil {
		tags = api.TagList{}
	}
	pair := KeyPairRecord{Key: key(ctx, id), Data: api.KeyPairInfo{
		KeyPairId: new(api.String(id)), KeyName: new(api.String(name)), KeyType: new(api.KeyType(kind)),
		KeyFingerprint: new(api.String(fingerprint)), PublicKey: new(api.String(public)), Tags: tags,
		CreateTime: new(api.MillisecondDateTime(s.clock.Now().UTC().Truncate(time.Millisecond))),
	}}
	return pair, tx.PutKeyPair(pair)
}

func (s *Service) createKeyPair(ctx context.Context, tx Transaction, in *api.CreateKeyPairRequest) (*api.KeyPair, error) {
	tags, err := CreationTags(in.TagSpecifications, "key-pair")
	if err != nil {
		return nil, err
	}
	name := str(in.KeyName)
	kind, format := str(in.KeyType), str(in.KeyFormat)
	if in.KeyType == nil {
		kind = "rsa"
	}
	if in.KeyFormat == nil {
		format = "pem"
	}
	if err := s.authorizeCreateWith(ctx, "CreateKeyPair", "key-pair", name, tags, map[string][]string{"ec2:KeyPairType": {kind}}); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if err := admitKeyPairName(ctx, tx, name); err != nil {
		return nil, err
	}
	if kind != "rsa" && kind != "ed25519" {
		return nil, failure("InvalidParameterValue", "1 validation error detected: Value '"+kind+"' at 'keyType' failed to satisfy constraint: Member must satisfy enum value set: [rsa, ed25519]")
	}
	if format != "pem" && format != "ppk" {
		return nil, failure("InvalidParameterValue", "1 validation error detected: Value '"+format+"' at 'keyFormat' failed to satisfy constraint: Member must satisfy enum value set: [ppk, pem]")
	}
	public, fingerprint, material, err := generateKeyPair(kind, format, name)
	if err != nil {
		return nil, err
	}
	pair, err := s.putNewKeyPair(ctx, tx, name, kind, public, fingerprint, tags)
	if err != nil {
		return nil, err
	}
	return &api.KeyPair{KeyPairId: pair.Data.KeyPairId, KeyName: pair.Data.KeyName, KeyFingerprint: pair.Data.KeyFingerprint, KeyMaterial: new(api.SensitiveUserData(material)), Tags: pair.Data.Tags}, nil
}

func (s *Service) importKeyPair(ctx context.Context, tx Transaction, in *api.ImportKeyPairRequest) (*api.ImportKeyPairResult, error) {
	tags, err := CreationTags(in.TagSpecifications, "key-pair")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCreate(ctx, "ImportKeyPair", "key-pair", str(in.KeyName), tags); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	name := str(in.KeyName)
	if err := admitKeyPairName(ctx, tx, name); err != nil {
		return nil, err
	}
	if len(in.PublicKeyMaterial) == 0 {
		return nil, failure("MissingParameter", "The request must contain the parameter PublicKeyMaterial")
	}
	public, err := parseKeyPairPublicKey(in.PublicKeyMaterial)
	if err != nil {
		return nil, err
	}
	fingerprint, err := keyPairFingerprint(public, nil)
	if err != nil {
		return nil, err
	}
	kind := "rsa"
	if public.Type() == ssh.KeyAlgoED25519 {
		kind = "ed25519"
	}
	material := keyPairPublicMaterial(public, name)
	pair, err := s.putNewKeyPair(ctx, tx, name, kind, material, fingerprint, tags)
	if err != nil {
		return nil, err
	}
	return &api.ImportKeyPairResult{KeyPairId: pair.Data.KeyPairId, KeyName: pair.Data.KeyName, KeyFingerprint: pair.Data.KeyFingerprint, Tags: tags}, nil
}

func keyPairByName(ctx context.Context, tx Reader, name string) (KeyPairRecord, error) {
	pairs, err := tx.KeyPairs(scopeFor(ctx))
	if err != nil {
		return KeyPairRecord{}, err
	}
	for _, pair := range pairs {
		if str(pair.Data.KeyName) == name {
			return pair, nil
		}
	}
	return KeyPairRecord{}, ErrNotFound
}

func validateKeyPairID(id string) error {
	valid := strings.HasPrefix(id, "key-") && len(id) == 21
	nonzero := false
	if valid {
		for _, c := range id[4:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				valid = false
				break
			}
			nonzero = nonzero || c != '0'
		}
	}
	if !valid || !nonzero {
		return failure("InvalidParameterValue", fmt.Sprintf("Invalid value '%s' for keyPairId.", id))
	}
	return nil
}

func (s *Service) describeKeyPairs(ctx context.Context, tx Transaction, in *api.DescribeKeyPairsRequest) (*api.DescribeKeyPairsResult, error) {
	if err := s.authorize(ctx, "DescribeKeyPairs", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if len(in.KeyNames) > 0 && len(in.KeyPairIds) > 0 {
		return nil, failure("InvalidParameterCombination", "The parameter 'keyPairId' may not be used in combination with 'keyName'")
	}
	pairs, err := tx.KeyPairs(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	byName := make(map[string]string, len(pairs))
	byID := make(map[string]api.KeyPairInfo, len(pairs))
	for _, pair := range pairs {
		byName[str(pair.Data.KeyName)] = pair.Key.ID
		byID[pair.Key.ID] = pair.Data
	}
	selected := make(map[string]bool, len(in.KeyPairIds)+len(in.KeyNames))
	for _, id := range in.KeyPairIds {
		if err := validateKeyPairID(string(id)); err != nil {
			return nil, err
		}
		if _, ok := byID[string(id)]; !ok {
			return nil, failure("InvalidParameterValue", fmt.Sprintf("Invalid value '%s' for keyPairId.", id))
		}
		selected[string(id)] = true
	}
	for _, name := range in.KeyNames {
		if strings.TrimSpace(string(name)) == "" {
			return nil, failure("InvalidParameterValue", "Invalid value '' for keyPairNames. It should not be blank")
		}
		id, ok := byName[string(name)]
		if !ok {
			return nil, missing("key-pair", string(name))
		}
		selected[id] = true
	}
	items := make([]pageItem, 0, len(pairs))
	for _, pair := range pairs {
		if len(selected) > 0 && !selected[pair.Key.ID] {
			continue
		}
		data := pair.Data
		if !boolValue(in.IncludePublicKey) {
			data.PublicKey = nil
		}
		items = append(items, pageItem{ID: pair.Key.ID, Tags: data.Tags, Fields: map[string][]string{
			"key-pair-id": {pair.Key.ID}, "key-name": {str(data.KeyName)}, "fingerprint": {str(data.KeyFingerprint)},
		}})
		byID[pair.Key.ID] = data
	}
	ids, _, err := selectPage(ctx, "DescribeKeyPairs", nil, in.Filters, nil, nil, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeKeyPairsResult{KeyPairs: api.KeyPairList{}}
	for _, id := range ids {
		out.KeyPairs = append(out.KeyPairs, byID[id])
	}
	return out, nil
}

func (s *Service) deleteKeyPair(ctx context.Context, tx Transaction, in *api.DeleteKeyPairRequest) (*api.DeleteKeyPairResult, error) {
	name, id := str(in.KeyName), str(in.KeyPairId)
	var pair KeyPairRecord
	var err error
	if id != "" {
		pair, err = tx.KeyPair(key(ctx, id))
	} else if name != "" {
		pair, err = keyPairByName(ctx, tx, name)
	} else {
		err = ErrNotFound
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	exists := err == nil
	authorizeName := name
	conditions := map[string][]string{}
	if exists {
		authorizeName = str(pair.Data.KeyName)
		conditions = keyPairConditions(pair.Data)
	} else if authorizeName == "" || id != "" {
		authorizeName = "*"
	}
	if err := s.authorizeWith(ctx, "DeleteKeyPair", "key-pair", authorizeName, pair.Data.Tags, conditions); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if name == "" && id == "" {
		return nil, failure("MissingParameter", "KeyName or KeyPairId must be provided")
	}
	if id != "" {
		if err := validateKeyPairID(id); err != nil {
			return nil, err
		}
	}
	out := &api.DeleteKeyPairResult{Return: new(api.Boolean(true))}
	if exists {
		if err := tx.DeleteKeyPair(pair.Key); err != nil {
			return nil, err
		}
		out.KeyPairId = pair.Data.KeyPairId
	}
	return out, nil
}

func keyPairConditions(pair api.KeyPairInfo) map[string][]string {
	return map[string][]string{"ec2:KeyPairName": {str(pair.KeyName)}, "ec2:KeyPairType": {str(pair.KeyType)}}
}
