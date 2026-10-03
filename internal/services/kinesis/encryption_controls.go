package kinesis

import (
	"context"
	"time"

	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
)

func registerEncryption(s *Service) {
	registerExternal(s, "StartStreamEncryption", s.startStreamEncryption)
	registerControl(s, "StopStreamEncryption", s.stopStreamEncryption)
}

func (s *Service) StartStreamEncryption(ctx context.Context, in *api.StartStreamEncryptionInput) (*api.StartStreamEncryptionOutput, *awswire.Error) {
	return runExternal(s, ctx, "StartStreamEncryption", in, s.startStreamEncryption)
}

func (s *Service) StopStreamEncryption(ctx context.Context, in *api.StopStreamEncryptionInput) (*api.StopStreamEncryptionOutput, *awswire.Error) {
	return runCommand(s, ctx, "StopStreamEncryption", in, s.stopStreamEncryption)
}

func validateEncryption(kind *api.EncryptionType, key *api.KeyId) error {
	if kind == nil || (*kind != api.EncryptionTypeKMS && *kind != api.EncryptionTypeNONE) {
		return failure("ValidationException", "EncryptionType must be KMS or NONE.")
	}
	if key == nil || len(*key) == 0 || len(*key) > 2048 {
		return failure("ValidationException", "KeyId must contain between 1 and 2048 characters.")
	}
	if *kind != api.EncryptionTypeKMS {
		return failure("InvalidArgumentException", "The only supported encryption type is KMS.")
	}
	return nil
}

// Start and Stop have separate documented rolling 24-hour limits. Count every
// accepted Start, including the native same-key UPDATING transition.
func encryptionHistory(stream StreamRecord, now time.Time, enabled bool) ([]EncryptionUpdate, error) {
	recent := make([]EncryptionUpdate, 0, len(stream.EncryptionUpdates)+1)
	count := 0
	for _, update := range stream.EncryptionUpdates {
		if update.At.After(now.Add(-24 * time.Hour)) {
			recent = append(recent, update)
			if update.Enabled == enabled {
				count++
			}
		}
	}
	if count >= 25 {
		return nil, failure("LimitExceededException", "Stream encryption changes exceed the rolling 24-hour limit.")
	}
	return append(recent, EncryptionUpdate{At: now, Enabled: enabled}), nil
}

func (s *Service) startStreamEncryption(ctx context.Context, in *api.StartStreamEncryptionInput) (*api.StartStreamEncryptionOutput, error) {
	if in == nil {
		return nil, failure("ValidationException", "Request must not be null.")
	}
	if err := validateEncryption(in.EncryptionType, in.KeyId); err != nil {
		return nil, err
	}
	var stream StreamRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		stream, err = s.stream(r.Context(), r, value(in.StreamName), value(in.StreamARN), "StartStreamEncryption")
		if err != nil {
			return err
		}
		if err = requireActive(stream); err != nil {
			return err
		}
		_, err = encryptionHistory(stream, s.clock.Now(), true)
		return err
	})
	if err != nil {
		return nil, err
	}
	if s.keys == nil {
		return nil, failure("KMSNotFoundException", "The KMS provider is unavailable.")
	}
	// Never nest a KMS transaction inside a repository callback or cache lock.
	arn, rejected := s.keys.ResolveKey(ctx, stream.Key, value(in.KeyId))
	if rejected != nil {
		return nil, rejected
	}
	key := arn
	if value(in.KeyId) == "alias/aws/kinesis" {
		key = "alias/aws/kinesis"
	}
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		current, err := s.stream(tx.Context(), tx, value(in.StreamName), value(in.StreamARN), "StartStreamEncryption")
		if err != nil {
			return err
		}
		if current.EngineID != stream.EngineID {
			return failure("ResourceInUseException", "The stream changed while the encryption key was being resolved.")
		}
		if err = requireActive(current); err != nil {
			return err
		}
		now := s.clock.Now()
		current.EncryptionUpdates, err = encryptionHistory(current, now, true)
		if err != nil {
			return err
		}
		return beginStreamUpdate(tx, current, StreamUpdate{AcceptedAt: now, EncryptionType: api.EncryptionTypeKMS, KeyID: key})
	})
	if err != nil {
		return nil, err
	}
	s.engines.wake()
	return &api.StartStreamEncryptionOutput{}, nil
}

func (s *Service) stopStreamEncryption(ctx context.Context, tx Transaction, in *api.StopStreamEncryptionInput) (*api.StopStreamEncryptionOutput, error) {
	if in == nil {
		return nil, failure("ValidationException", "Request must not be null.")
	}
	if err := validateEncryption(in.EncryptionType, in.KeyId); err != nil {
		return nil, err
	}
	stream, err := s.stream(ctx, tx, value(in.StreamName), value(in.StreamARN), "StopStreamEncryption")
	if err != nil {
		return nil, err
	}
	if err = requireActive(stream); err != nil {
		return nil, err
	}
	if value(stream.Data.EncryptionType) != string(api.EncryptionTypeKMS) {
		return nil, failure("InvalidArgumentException", "Cannot stop encrypting an unencrypted stream.")
	}
	now := s.clock.Now()
	stream.EncryptionUpdates, err = encryptionHistory(stream, now, false)
	if err != nil {
		return nil, err
	}
	// Stopping does not require a usable KMS key. Retained encrypted records
	// carry their original key; disabling the stream setting cannot decrypt them.
	if err = beginStreamUpdate(tx, stream, StreamUpdate{AcceptedAt: now, EncryptionType: api.EncryptionTypeNONE}); err != nil {
		return nil, err
	}
	return &api.StopStreamEncryptionOutput{}, nil
}
