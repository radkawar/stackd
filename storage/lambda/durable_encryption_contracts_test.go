package lambda_test

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	api "stackd/internal/awsapi/lambda"
	"stackd/storage/lambda"
	"stackd/storage/sqlite"
	sqllambda "stackd/storage/sqlite/lambda"
)

// Ciphertext is produced with a deterministic test-only key and unique nonces.
// The repository owns lossless persistence, not KMS or payload encryption.
func encryptedDurableFixture(t *testing.T) lambda.DurableExecutionRecord {
	t.Helper()
	block, err := aes.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	var sequence byte
	seal := func(input []byte) []byte {
		sequence++
		nonce := make([]byte, aead.NonceSize())
		nonce[len(nonce)-1] = sequence
		return aead.Seal(nonce, nonce, input, []byte("durable-storage-contract"))
	}
	text := func(input string) string { return base64.StdEncoding.EncodeToString(seal([]byte(input))) }
	protectError := func(input *api.ErrorObject) *api.ErrorObject {
		if input == nil {
			return nil
		}
		out := &api.ErrorObject{}
		if input.ErrorData != nil {
			out.ErrorData = new(api.ErrorData(text(string(*input.ErrorData))))
		}
		if input.ErrorMessage != nil {
			out.ErrorMessage = new(api.ErrorMessage(text(string(*input.ErrorMessage))))
		}
		if input.ErrorType != nil {
			out.ErrorType = new(api.ErrorType(text(string(*input.ErrorType))))
		}
		if input.StackTrace != nil {
			out.StackTrace = make(api.StackTraceEntries, len(input.StackTrace))
			for i, frame := range input.StackTrace {
				out.StackTrace[i] = api.StackTraceEntry(text(string(frame)))
			}
		}
		return out
	}
	protectOperation := func(v lambda.DurableOperationRecord) lambda.DurableOperationRecord {
		if v.Payload != nil {
			v.Payload = new(text(*v.Payload))
		}
		v.Error = protectError(v.Error)
		return v
	}
	v := durableExecutionFixture()
	v.KeyARN, v.WrappedKey, v.Encrypted = "arn:aws:kms:us-east-1:111111111111:key/durable", seal([]byte("per-execution-data-key")), true
	v.Input, v.Result, v.Error = new(text(*v.Input)), new(text(`{"charged":true}`)), protectError(v.Error)
	for i := range v.Operations {
		v.Operations[i] = protectOperation(v.Operations[i])
	}
	for i := range v.History {
		v.History[i].Operation = protectOperation(v.History[i].Operation)
	}
	for i := range v.Checkpoints {
		v.Checkpoints[i].Request = seal(v.Checkpoints[i].Request)
		for j := range v.Checkpoints[i].Operations {
			v.Checkpoints[i].Operations[j] = protectOperation(v.Checkpoints[i].Operations[j])
		}
	}
	return v
}

func TestDurableEncryptedStateAndKeyIdentity(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		want, input := encryptedDurableFixture(t), encryptedDurableFixture(t)
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutDurableExecution(input); err != nil {
				return err
			}
			input.WrappedKey[0] ^= 0xff
			input.Checkpoints[0].Request[0] ^= 0xff
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		assertDurableExecution(t, repo, want)
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			v, err := r.DurableExecution(want.ARN)
			if err != nil {
				return err
			}
			v.WrappedKey[0] ^= 0xff
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		assertDurableExecution(t, repo, want)
		for _, mutate := range []func(*lambda.DurableExecutionRecord){
			func(v *lambda.DurableExecutionRecord) { v.KeyARN += "-replacement" },
			func(v *lambda.DurableExecutionRecord) { v.WrappedKey[0] ^= 0xff },
			func(v *lambda.DurableExecutionRecord) { v.Encrypted = false },
		} {
			v := encryptedDurableFixture(t)
			mutate(&v)
			if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutDurableExecution(v) }); err == nil {
				t.Fatal("execution encryption identity was changed")
			}
		}
		assertDurableExecution(t, repo, want)
		abort := errors.New("abort encrypted checkpoint")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			v, err := tx.DurableExecution(want.ARN)
			if err != nil {
				return err
			}
			v.Token, v.Checkpoints = "new-checkpoint-token", nil
			if err := tx.PutDurableExecution(v); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatalf("encrypted checkpoint rollback: %v", err)
		}
		assertDurableExecution(t, repo, want)
	})
}

func TestDurableEncryptedStateReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "encrypted-durable.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	want := encryptedDurableFixture(t)
	if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutDurableExecution(want) }); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	repo := sqllambda.New(db)
	assertDurableExecution(t, repo, want)
	// A resumed worker may advance its token/claim, but never the admitted CMK.
	want.Token, want.Claimed = "recovered-token", false
	if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutDurableExecution(want) }); err != nil {
		t.Fatal(err)
	}
	assertDurableExecution(t, repo, want)
}
