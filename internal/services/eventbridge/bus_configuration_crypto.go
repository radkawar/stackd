package eventbridge

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/json"
	"errors"

	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/inputtransform"
)

func (s *Service) configurationCipher(ctx context.Context, bus BusRecord, caller bool) (cipher.AEAD, *awswire.Error) {
	if len(bus.ConfigurationDataKey) == 0 {
		return nil, nil
	}
	if s.busKeys == nil {
		return nil, unsupported("No event bus KMS provider is configured.")
	}
	var plain []byte
	var rejected *awswire.Error
	if caller {
		plain, rejected = s.busKeys.DecryptBusConfiguration(ctx, bus.Key, bus.ConfigurationDataKey)
	} else {
		plain, rejected = s.busKeys.DecryptBusDataKey(ctx, bus.Key, bus.ConfigurationDataKey)
	}
	if rejected != nil {
		return nil, rejected
	}
	defer clear(plain)
	aead, err := archiveCipher(plain)
	if err != nil {
		return nil, failure("InternalException", "Unable to initialize configuration encryption.", 500)
	}
	return aead, nil
}

func (s *Service) newConfigurationKey(ctx context.Context, bus *BusRecord) (cipher.AEAD, *awswire.Error) {
	if bus.KmsKeyIdentifier == "" {
		bus.ConfigurationDataKey, bus.ConfigurationKeyARN = nil, ""
		return nil, nil
	}
	plain, wrapped, arn, rejected := s.busKeys.GenerateBusDataKey(ctx, bus.Key, bus.KmsKeyIdentifier)
	if rejected != nil {
		return nil, rejected
	}
	defer clear(plain)
	aead, err := archiveCipher(plain)
	if err != nil {
		return nil, failure("InternalException", "Unable to initialize configuration encryption.", 500)
	}
	bus.ConfigurationDataKey, bus.ConfigurationKeyARN = wrapped, arn
	return aead, nil
}

func openRuleConfiguration(rule RuleRecord, aead cipher.AEAD) (RuleRecord, error) {
	if len(rule.EncryptedPattern) == 0 {
		return rule, nil
	}
	if aead == nil {
		return RuleRecord{}, failure("InternalException", "Missing rule encryption key.", 500)
	}
	plain, rejected := openEnvelope(aead, rule.EncryptedPattern)
	if rejected != nil {
		return RuleRecord{}, rejected
	}
	rule.Pattern, rule.EncryptedPattern = string(plain), nil
	return rule, nil
}
func sealRuleConfiguration(rule RuleRecord, aead cipher.AEAD) RuleRecord {
	if aead != nil && rule.Pattern != "" {
		rule.EncryptedPattern, rule.Pattern = sealEnvelope(aead, []byte(rule.Pattern)), ""
	}
	return rule
}
func openTargetConfiguration(target TargetRecord, aead cipher.AEAD) (TargetRecord, error) {
	if len(target.EncryptedConfiguration) == 0 {
		return target, nil
	}
	if aead == nil {
		return TargetRecord{}, failure("InternalException", "Missing target encryption key.", 500)
	}
	plain, rejected := openEnvelope(aead, target.EncryptedConfiguration)
	if rejected != nil {
		return TargetRecord{}, rejected
	}
	var result TargetRecord
	if err := json.Unmarshal(plain, &result); err != nil {
		return TargetRecord{}, err
	}
	return result, nil
}
func sealTargetConfiguration(target TargetRecord, aead cipher.AEAD) (TargetRecord, error) {
	if aead == nil {
		return target, nil
	}
	target.EncryptedConfiguration = nil
	plain, err := json.Marshal(target)
	if err != nil {
		return TargetRecord{}, err
	}
	target.EncryptedConfiguration = sealEnvelope(aead, plain)
	// Routing identities and retry policy are metadata. Customer input,
	// transforms and destination-specific configuration exist only in ciphertext.
	target.Input, target.EcsParameters, target.KinesisParameters = inputtransform.Definition{}, nil, nil
	target.HttpParameters = nil
	target.MessageGroupID = ""
	return target, nil
}

type configurationReader struct {
	Reader
	cipher cipher.AEAD
}

func (r configurationReader) Rule(key RuleKey) (RuleRecord, error) {
	v, err := r.Reader.Rule(key)
	if err != nil {
		return v, err
	}
	return openRuleConfiguration(v, r.cipher)
}
func (r configurationReader) Rules(key BusKey) ([]RuleRecord, error) {
	rows, err := r.Reader.Rules(key)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i], err = openRuleConfiguration(rows[i], r.cipher)
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (r configurationReader) Targets(key RuleKey) ([]TargetRecord, error) {
	rows, err := r.Reader.Targets(key)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i], err = openTargetConfiguration(rows[i], r.cipher)
		if err != nil {
			return nil, err
		}
	}
	return rows, nil
}

type configurationTransaction struct {
	Transaction
	reader configurationReader
}

func (t configurationTransaction) Rule(key RuleKey) (RuleRecord, error)   { return t.reader.Rule(key) }
func (t configurationTransaction) Rules(key BusKey) ([]RuleRecord, error) { return t.reader.Rules(key) }
func (t configurationTransaction) Targets(key RuleKey) ([]TargetRecord, error) {
	return t.reader.Targets(key)
}
func (t configurationTransaction) PutRule(rule RuleRecord) error {
	return t.Transaction.PutRule(sealRuleConfiguration(rule, t.reader.cipher))
}
func (t configurationTransaction) PutTarget(target TargetRecord) error {
	sealed, err := sealTargetConfiguration(target, t.reader.cipher)
	if err != nil {
		return err
	}
	return t.Transaction.PutTarget(sealed)
}

// configUpdate unwraps before entering the resource transaction and fences the
// wrapped configuration key against concurrent bus replacement/reset.
func (s *Service) configUpdate(ctx context.Context, key BusKey, caller bool, fn func(Transaction) error) error {
	var selected BusRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		selected, err = r.Bus(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}); err != nil {
		return err
	}
	aead, rejected := s.configurationCipher(ctx, selected, caller)
	if rejected != nil {
		return rejected
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Bus(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if !bytes.Equal(current.ConfigurationDataKey, selected.ConfigurationDataKey) {
			return failure("ConcurrentModificationException", "Event bus encryption configuration changed during the operation.")
		}
		return fn(configurationTransaction{Transaction: tx, reader: configurationReader{Reader: tx, cipher: aead}})
	})
}
