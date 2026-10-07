package integrations

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"maps"
	"reflect"
	"testing"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
	service "stackd/internal/services/lambda"
)

// Seed a previously admitted deployment, including its native private claim and
// retained ZIP. Recovery and mutations then use the real owner commands.
func cfnLambdaSeedDeployment(t *testing.T, f *cfnLambdaAdditionalFixture) (cloudformation.ResourceRequest, service.FunctionKey) {
	t.Helper()
	const source = "def handler(event, context): return 'deployed'"
	r := cfnLambdaAdditionalRequest("AWS::Lambda::Function", cloudformation.Properties{
		"FunctionName": "configured",
		"Runtime":      "python3.12",
		"Handler":      "index.handler",
		"Role":         "arn:aws:iam::111111111111:role/execution",
		"Code":         map[string]any{"ZipFile": source},
	})
	r.PhysicalID = "configured"
	key := service.FunctionKey{Scope: service.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: r.PhysicalID}
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	file, err := archive.Create("index.py")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(source)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	code := buffer.Bytes()
	digest := sha256.Sum256(code)
	sha := base64.StdEncoding.EncodeToString(digest[:])
	if err := f.repo.Update(f.ctx, func(tx service.Transaction) error {
		record, err := tx.Function(key)
		if err != nil {
			return err
		}
		record.Owner = service.FunctionOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}
		record.Tags = cfnLambdaDeploymentTags(r)
		record.CodeSHA256, record.CodeSize = sha, int64(len(code))
		if err := tx.PutCodeArchive(service.CodeArchive{Key: service.CodeArchiveKey{Scope: key.Scope, SHA256: sha}, Code: code, CreatedAt: f.manual.Now()}); err != nil {
			return err
		}
		return tx.PutFunction(record)
	}); err != nil {
		t.Fatal(err)
	}
	if result, err := (cfnLambdaFunction{f.commands}).Create(f.ctx, r); err != nil || result.PhysicalID != key.Name {
		t.Fatalf("private admission recovery: %+v %v", result, err)
	}
	return r, key
}

func cfnLambdaDeploymentRecord(t *testing.T, f *cfnLambdaAdditionalFixture, key service.FunctionKey) service.FunctionRecord {
	t.Helper()
	var record service.FunctionRecord
	if err := f.repo.View(f.ctx, func(reader service.Reader) error { var err error; record, err = reader.Function(key); return err }); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestCFNLambdaDirectConfigurationOnlyUpdateAndDelete(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			original, key := cfnLambdaSeedDeployment(t, f)
			before := cfnLambdaDeploymentRecord(t, f, key)
			f.reopen(t)
			h := cfnLambdaFunction{f.commands}
			r := original
			r.CloudControl = true
			r.StackID = "direct-update-request"
			r.Token = "new-request-token"
			properties, err := h.Read(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := properties["Code"]; present {
				t.Fatal("write-only Code leaked")
			}
			r.Previous = maps.Clone(original.Properties)
			delete(r.Previous, "Code")
			r.Properties = maps.Clone(r.Previous)
			r.Properties["Tags"] = []any{map[string]any{"Key": "customer", "Value": "updated"}}
			if err := h.Validate(r.Properties); err == nil {
				t.Fatal("create accepted absent Code")
			}
			if err := h.ValidateUpdate(r.Previous, r.Properties); err != nil {
				t.Fatal(err)
			}
			if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil || replacement {
				t.Fatalf("configuration update requires replacement: %v %v", replacement, err)
			}
			if result, err := h.Update(f.ctx, r); err != nil || result.PhysicalID != original.PhysicalID {
				t.Fatalf("direct update: %+v %v", result, err)
			}
			if ready, err := h.Stabilize(f.ctx, r); err != nil || !ready {
				t.Fatalf("config-only tag update attempted redeployment: %v %v", ready, err)
			}
			after := cfnLambdaDeploymentRecord(t, f, key)
			if after.CodeSHA256 != before.CodeSHA256 || after.DeploymentRevision != before.DeploymentRevision || after.Owner != before.Owner || after.Tags[cfnComputeTagPrefix+"code"] != before.Tags[cfnComputeTagPrefix+"code"] || after.Tags[cfnComputeTagPrefix+"last-admission"] != before.Tags[cfnComputeTagPrefix+"last-admission"] {
				t.Fatalf("configuration-only request altered deployment/owner: before=%+v after=%+v", before, after)
			}
			if after.Tags["customer"] != "updated" {
				t.Fatalf("customer tags did not converge: %+v", after.Tags)
			}

			// A real configuration change reaches the native owner. Missing runtime
			// prerequisites must fail without marking the desired document ready.
			r.Properties["Description"] = "requires native configuration update"
			f.authority.denied = "lambda:UpdateFunctionConfiguration"
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if ready, err := h.Stabilize(f.ctx, r); ready || !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("configuration mutation bypassed current IAM: %v %v", ready, err)
			}
			f.authority.denied = ""
			if ready, err := h.Stabilize(f.ctx, r); ready || !cfnMessagingMissing(err, "NotImplementedException") {
				t.Fatalf("missing runtime was reported as convergence: %v %v", ready, err)
			}
			rejected := cfnLambdaDeploymentRecord(t, f, key)
			if rejected.Description != after.Description || !reflect.DeepEqual(rejected.Tags, after.Tags) || rejected.CodeSHA256 != after.CodeSHA256 {
				t.Fatal("rejected configuration update changed native deployment or readiness tags")
			}

			r.StackID, r.Token = "direct-delete-request", "delete-request-token"
			f.authority.denied = "lambda:DeleteFunction"
			if err := h.Delete(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("direct delete bypassed current IAM: %v", err)
			}
			f.authority.denied = ""
			f.reopen(t)
			h.commands = f.commands
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Read(f.ctx, r); !cfnComputeMissing(err) {
				t.Fatalf("direct delete left native function: %v", err)
			}
		})
	}
}

func TestCFNLambdaDurabilityRemovalRejectsBeforeEffects(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			original, key := cfnLambdaSeedDeployment(t, f)
			if err := f.repo.Update(f.ctx, func(tx service.Transaction) error {
				record, err := tx.Function(key)
				if err != nil {
					return err
				}
				record.Durable = &api.DurableConfig{ExecutionTimeout: new(api.ExecutionTimeout(60)), RetentionPeriodInDays: new(api.RetentionPeriodInDays(7))}
				return tx.PutFunction(record)
			}); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			h := cfnLambdaFunction{f.commands}
			r := original
			r.CloudControl = true
			r.Token = "remove-durability"
			previous := maps.Clone(original.Properties)
			delete(previous, "Code")
			previous["DurableConfig"] = map[string]any{"ExecutionTimeout": 60, "RetentionPeriodInDays": 7}
			observed, err := h.Read(f.ctx, r)
			if err != nil || observed["DurableConfig"] == nil {
				t.Fatalf("native durability was not retained: %+v %v", observed, err)
			}
			r.Previous = previous
			r.Properties = maps.Clone(previous)
			delete(r.Properties, "DurableConfig")
			r.Properties["Description"] = "must not apply"
			before := cfnLambdaDeploymentRecord(t, f, key)
			if err := h.ValidateUpdate(previous, r.Properties); err == nil {
				t.Fatal("durability removal passed validation")
			}
			if _, err := h.Update(f.ctx, r); err == nil {
				t.Fatal("durability removal was admitted")
			}
			if ready, err := h.Stabilize(f.ctx, r); ready || err == nil {
				t.Fatalf("durability removal converged: %v %v", ready, err)
			}
			after := cfnLambdaDeploymentRecord(t, f, key)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("rejected durability removal changed native state")
			}
		})
	}
}

func TestCFNLambdaRollbackUsesActualDurabilityAndCreateRecoveryKeepsID(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			original, key := cfnLambdaSeedDeployment(t, f)
			f.reopen(t)
			h := cfnLambdaFunction{f.commands}
			rollback := original
			rollback.Previous = cloudformation.Properties{"DurableConfig": map[string]any{"ExecutionTimeout": 60}}
			// A failed enable-durability update did not change the actual native state.
			if _, err := h.Update(f.ctx, rollback); err != nil {
				t.Fatalf("unchanged old deployment rejected during rollback: %v", err)
			}
			if ready, err := h.Stabilize(f.ctx, rollback); !ready || err != nil {
				t.Fatalf("unchanged rollback did not converge: %v %v", ready, err)
			}
			replay := original
			replay.Properties = maps.Clone(original.Properties)
			replay.Properties["Code"] = nil
			if result, err := h.Create(f.ctx, replay); err == nil || result.PhysicalID != key.Name {
				t.Fatalf("admitted same-token replay lost real ID on validation failure: %+v %v", result, err)
			}
			f.authority.denied = "lambda:ListTags"
			if result, err := h.Create(f.ctx, original); !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != key.Name {
				t.Fatalf("admitted incarnation lost real ID on later tag authorization failure: %+v %v", result, err)
			}
			f.authority.denied = ""
			foreign := replay
			foreign.Token = "foreign"
			foreign.CloudControl = true
			if result, err := h.Create(f.ctx, foreign); !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != "" {
				t.Fatalf("direct create adopted existing foreign incarnation: %+v %v", result, err)
			}
		})
	}
}
