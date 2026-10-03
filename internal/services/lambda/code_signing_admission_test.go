package lambda

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func TestCodeSigningWarnDoesNotBypassIntegrity(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/lambda/code_signing_local.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Signed   string `json:"signedZipBase64"`
		Unsigned string `json:"unsignedZipBase64"`
		Root     string `json:"trustedRootCertificateBase64"`
		Profile  string `json:"profileVersionArn"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	signed, err := base64.StdEncoding.DecodeString(fixture.Signed)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := base64.StdEncoding.DecodeString(fixture.Unsigned)
	if err != nil {
		t.Fatal(err)
	}
	root, err := base64.StdEncoding.DecodeString(fixture.Root)
	if err != nil {
		t.Fatal(err)
	}
	source, err := zip.NewReader(bytes.NewReader(signed), int64(len(signed)))
	if err != nil {
		t.Fatal(err)
	}
	var changed bytes.Buffer
	writer := zip.NewWriter(&changed)
	for _, entry := range source.File {
		r, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		contents, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name == "handler.py" {
			contents = append(contents, []byte("# tampered\n")...)
		}
		w, err := writer.Create(entry.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	scope := Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region})
	service := New(Config{
		Clock:                clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
		CodeSigningAuthority: fixtureSigningAuthority{roots: [][]byte{root}},
	})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	config := CodeSigningConfigRecord{Key: CodeSigningConfigKey{Scope: scope, ID: "csc-0123456789abcdef0"}, Policy: "Warn", Publishers: []string{fixture.Profile}, Modified: service.clock.Now()}
	if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutCodeSigningConfig(config) }); err != nil {
		t.Fatal(err)
	}
	key := FunctionKey{Scope: scope, Name: "admission"}
	if _, wire := service.prepareCodeSigning(ctx, key, config.Key.ARN(), signed, nil); wire != nil {
		t.Fatalf("valid locally re-signed fixture rejected: %v", wire)
	}
	if _, wire := service.prepareCodeSigning(ctx, key, config.Key.ARN(), unsigned, nil); wire != nil {
		t.Fatalf("Warn rejected unsigned deployment: %v", wire)
	}
	if _, wire := service.prepareCodeSigning(ctx, key, config.Key.ARN(), changed.Bytes(), nil); wire == nil || wire.Code != "CodeVerificationFailedException" {
		t.Fatalf("Warn bypassed integrity: %v", wire)
	}
	config.Policy = "Enforce"
	if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutCodeSigningConfig(config) }); err != nil {
		t.Fatal(err)
	}
	if _, wire := service.prepareCodeSigning(ctx, key, config.Key.ARN(), unsigned, nil); wire == nil || wire.Code != "CodeVerificationFailedException" {
		t.Fatalf("Enforce admitted unsigned deployment: %v", wire)
	}
}

// Fixture authority is test-local; production roots and revocation state are untouched.
type fixtureSigningAuthority struct {
	roots       [][]byte
	revokedJobs map[string]bool
}

func (a fixtureSigningAuthority) CodeSigningRoots(context.Context) ([][]byte, error) {
	return a.roots, nil
}

func (a fixtureSigningAuthority) Revoked(_ context.Context, signature CodeSignature) (bool, error) {
	return a.revokedJobs[signature.SigningJobARN], nil
}

func TestCodeSigningPolicyChangeFencesPreparedDeployment(t *testing.T) {
	scope := Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region})
	service := New(Config{})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	config := CodeSigningConfigRecord{Key: CodeSigningConfigKey{Scope: scope, ID: "csc-0123456789abcdef0"}, Policy: "Warn", Publishers: []string{"arn:aws:signer:us-east-1:111111111111:/signing-profiles/release/0123456789"}, Modified: service.clock.Now()}
	if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutCodeSigningConfig(config) }); err != nil {
		t.Fatal(err)
	}
	key := FunctionKey{Scope: scope, Name: "admission"}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	w, err := writer.Create("handler.py")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("def handler(event, context): return event\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	prepared, wire := service.prepareCodeSigning(ctx, key, config.Key.ARN(), archive.Bytes(), nil)
	if wire != nil {
		t.Fatal(wire)
	}
	// Keep Modified unchanged: comparison must fence actual policy contents,
	// not rely on a wall-clock timestamp that can repeat under manual time.
	config.Policy = "Enforce"
	if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutCodeSigningConfig(config) }); err != nil {
		t.Fatal(err)
	}
	err = service.repository.Update(ctx, func(tx Transaction) error { return prepared.commit(tx, true) })
	var conflict *awswire.Error
	if !errors.As(err, &conflict) || conflict.Code != "ResourceConflictException" {
		t.Fatalf("stale verification admitted stronger policy: %v", err)
	}
	if err := service.repository.View(ctx, func(r Reader) error {
		if _, err := r.FunctionCodeSigningConfig(key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rejected admission left attachment: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
