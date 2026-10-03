package lambda

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// DurableEncryption delegates key policy and caller/session evaluation to KMS.
// These methods run before Lambda repository transactions, never from readers.
type DurableEncryption interface {
	Validate(context.Context, FunctionKey, string) (string, *awswire.Error)
	Generate(context.Context, FunctionKey, string) ([]byte, []byte, *awswire.Error)
	Open(context.Context, FunctionKey, []byte, bool) ([]byte, *awswire.Error)
}

type durableMaterialKey struct{}
type durableDataAccessKey struct{}
type durableMaterial struct {
	function       FunctionVersionKey
	keyARN         string
	wrapped, plain []byte
}

func (s *Service) validateDurableEncryption(ctx context.Context, function *FunctionRecord) *awswire.Error {
	if function.Durable == nil || value(function.Durable.KMSKeyArn) == "" {
		return nil
	}
	if s.durableEncryption == nil {
		return unsupported("Durable execution KMS authority is not configured.")
	}
	key, rejected := s.durableEncryption.Validate(ctx, function.Key, value(function.Durable.KMSKeyArn))
	if rejected != nil {
		return rejected
	}
	function.Durable.KMSKeyArn = new(api.KMSKeyArn(key))
	return nil
}

func (s *Service) prepareDurableContext(ctx context.Context, arn, action string, processing bool) (context.Context, *awswire.Error) {
	ctx = context.WithValue(ctx, durableMaterialKey{}, (*durableMaterial)(nil))
	var record DurableExecutionRecord
	lookup := context.WithValue(ctx, durableDataAccessKey{}, false)
	err := s.repository.View(lookup, func(r Reader) error {
		var err error
		if processing {
			record, err = r.DurableExecution(arn)
		} else {
			record, err = s.authorizedDurable(r, arn, action)
		}
		return err
	})
	if err != nil {
		return ctx, wireError(err)
	}
	ctx = context.WithValue(ctx, durableDataAccessKey{}, true)
	if !record.Encrypted {
		return ctx, nil
	}
	if s.durableEncryption == nil {
		return ctx, unsupported("Durable execution KMS authority is not configured.")
	}
	plain, rejected := s.durableEncryption.Open(ctx, record.Function.FunctionKey, record.WrappedKey, processing)
	if rejected != nil {
		if processing || action == "CheckpointDurableExecution" {
			switch rejected.Code {
			case "KMSAccessDeniedException", "KMSDisabledException", "KMSInvalidStateException", "KMSNotFoundException":
				if err := s.failDurableEncryption(ctx, record); err != nil {
					return ctx, wireError(err)
				}
			}
		}
		return ctx, rejected
	}
	return context.WithValue(ctx, durableMaterialKey{}, &durableMaterial{function: record.Function, keyARN: record.KeyARN, wrapped: record.WrappedKey, plain: plain}), nil
}

// An unavailable key is a non-retryable checkpoint failure. Metadata remains
// inspectable without the key; previously encrypted payloads are not rewritten.
func (s *Service) failDurableEncryption(ctx context.Context, snapshot DurableExecutionRecord) error {
	err := s.repository.Update(context.WithoutCancel(ctx), func(tx Transaction) error {
		current, err := tx.DurableExecution(snapshot.ARN)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Status != "RUNNING" || current.KeyARN != snapshot.KeyARN || !bytes.Equal(current.WrappedKey, snapshot.WrappedKey) {
			return nil
		}
		completeDurable(&current, "FAILED", nil, nil, s.clock.Now())
		return tx.PutDurableExecution(current)
	})
	if err == nil {
		s.durable.stop(snapshot.ARN)
		s.durable.changed()
		s.jobs.Wake()
	}
	return err
}

func (s *Service) prepareDurableStart(ctx context.Context, function FunctionRecord, name, kind string) (context.Context, *awswire.Error) {
	ctx = context.WithValue(ctx, durableMaterialKey{}, (*durableMaterial)(nil))
	// The idempotency identity outlives configuration changes; inspect existing
	// executions before selecting the current version's encryption key.
	var existing *DurableExecutionRecord
	if name != "" {
		err := s.repository.View(ctx, func(r Reader) error {
			rows, err := r.DurableExecutions()
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Function.Scope == function.Key.Scope && row.Name == name && (row.ExpiresAt.IsZero() || s.clock.Now().Before(row.ExpiresAt)) {
					existing = &row
					break
				}
			}
			return nil
		})
		if err != nil {
			return ctx, wireError(err)
		}
	}
	if existing != nil {
		if kind == "Event" {
			return ctx, nil
		}
		return s.prepareDurableContext(ctx, existing.ARN, "InvokeFunction", true)
	}
	ctx = context.WithValue(ctx, durableDataAccessKey{}, true)
	keyARN := value(function.Durable.KMSKeyArn)
	if keyARN == "" {
		return ctx, nil
	}
	if s.durableEncryption == nil {
		return ctx, unsupported("Durable execution KMS authority is not configured.")
	}
	plain, wrapped, rejected := s.durableEncryption.Generate(ctx, function.Key, keyARN)
	if rejected != nil {
		return ctx, rejected
	}
	return context.WithValue(ctx, durableMaterialKey{}, &durableMaterial{function: FunctionVersionKey{FunctionKey: function.Key, Version: function.Version}, keyARN: keyARN, wrapped: wrapped, plain: plain}), nil
}

func bindDurableEncryption(ctx context.Context, record *DurableExecutionRecord, function FunctionRecord) error {
	record.KeyARN = value(function.Durable.KMSKeyArn)
	if record.KeyARN == "" {
		return nil
	}
	material, _ := ctx.Value(durableMaterialKey{}).(*durableMaterial)
	if material == nil || material.function != record.Function || material.keyARN != record.KeyARN {
		return failure("ResourceConflictException", "Durable encryption configuration changed while starting the execution.", 409)
	}
	record.WrappedKey = bytes.Clone(material.wrapped)
	return nil
}

func clearDurableMaterial(ctx context.Context) {
	if material, _ := ctx.Value(durableMaterialKey{}).(*durableMaterial); material != nil {
		clear(material.plain)
	}
}

func readPreparedDurable(r Reader, arn string) (DurableExecutionRecord, error) {
	record, err := r.DurableExecution(arn)
	if err != nil {
		return record, err
	}
	return cryptDurableRecord(r.Context(), record, true)
}

func putPreparedDurable(tx Transaction, record DurableExecutionRecord) error {
	if record.Encrypted {
		return fmt.Errorf("durable execution %s must be decrypted before payload mutation", record.ARN)
	}
	encrypted, err := cryptDurableRecord(tx.Context(), record, false)
	if err != nil {
		return err
	}
	return tx.PutDurableExecution(encrypted)
}

func cryptDurableRecord(ctx context.Context, record DurableExecutionRecord, decrypt bool) (DurableExecutionRecord, error) {
	if record.KeyARN == "" || (decrypt && !record.Encrypted) {
		return record, nil
	}
	material, _ := ctx.Value(durableMaterialKey{}).(*durableMaterial)
	if material == nil || material.function != record.Function || material.keyARN != record.KeyARN || !bytes.Equal(material.wrapped, record.WrappedKey) {
		return record, failure("ResourceConflictException", "Durable encryption material no longer matches this execution.", 409)
	}
	block, err := aes.NewCipher(material.plain)
	if err != nil {
		return record, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return record, err
	}
	out := cloneDurableExecution(record)
	crypt := func(data []byte, path string) ([]byte, error) {
		aad := []byte(record.ARN + "\x00" + path)
		if decrypt {
			if len(data) < aead.NonceSize() {
				return nil, fmt.Errorf("invalid durable encrypted payload at %s", path)
			}
			return aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], aad)
		}
		nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		return aead.Seal(nonce, nonce, data, aad), nil
	}
	text := func(value *string, path string) error {
		if value == nil {
			return nil
		}
		data := []byte(*value)
		if decrypt {
			var err error
			data, err = base64.RawStdEncoding.DecodeString(*value)
			if err != nil {
				return err
			}
		}
		data, err := crypt(data, path)
		if err != nil {
			return err
		}
		if decrypt {
			*value = string(data)
		} else {
			*value = base64.RawStdEncoding.EncodeToString(data)
		}
		return nil
	}
	object := func(value *api.ErrorObject, path string) error {
		if value == nil {
			return nil
		}
		if err := cryptDurableText(value.ErrorType, path+"/type", text); err != nil {
			return err
		}
		if err := cryptDurableText(value.ErrorMessage, path+"/message", text); err != nil {
			return err
		}
		if err := cryptDurableText(value.ErrorData, path+"/data", text); err != nil {
			return err
		}
		for i := range value.StackTrace {
			if err := cryptDurableText(&value.StackTrace[i], path+"/stack/"+strconv.Itoa(i), text); err != nil {
				return err
			}
		}
		return nil
	}
	operation := func(value *DurableOperationRecord, path string) error {
		if err := text(value.Payload, path+"/payload"); err != nil {
			return err
		}
		return object(value.Error, path+"/error")
	}
	if err := text(out.Input, "input"); err != nil {
		return record, err
	}
	if err := text(out.Result, "result"); err != nil {
		return record, err
	}
	if err := object(out.Error, "error"); err != nil {
		return record, err
	}
	for i := range out.Operations {
		if err := operation(&out.Operations[i], "operation/"+out.Operations[i].ID); err != nil {
			return record, err
		}
	}
	for i := range out.History {
		if err := operation(&out.History[i].Operation, "history/"+strconv.Itoa(int(out.History[i].ID))); err != nil {
			return record, err
		}
	}
	for i := range out.Checkpoints {
		checkpoint := &out.Checkpoints[i]
		path := "checkpoint/" + checkpoint.ClientToken
		checkpoint.Request, err = crypt(checkpoint.Request, path+"/request")
		if err != nil {
			return record, err
		}
		for j := range checkpoint.Operations {
			if err := operation(&checkpoint.Operations[j], path+"/operation/"+checkpoint.Operations[j].ID); err != nil {
				return record, err
			}
		}
	}
	out.Encrypted = !decrypt
	return out, nil
}

func cryptDurableText[T ~string](value *T, path string, crypt func(*string, string) error) error {
	if value == nil {
		return nil
	}
	text := string(*value)
	if err := crypt(&text, path); err != nil {
		return err
	}
	*value = T(text)
	return nil
}
