package integrations

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	ccapi "stackd/internal/awsapi/cloudcontrol"
	glueapi "stackd/internal/awsapi/glue"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudcontrol"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/glue"
	"stackd/internal/services/kms"
	"stackd/storage/memory"
)

func TestGlueConnectionCloudControlRedactionAndCredentialRetention(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plaintext"
		if encrypted {
			name = "kms-encrypted"
		}
		t.Run(name, func(t *testing.T) {
			ctx := cfnAnalyticsTestContext()
			domain := memory.NewDomain()
			keys := kms.NewWithStorage(kms.NewMemoryStorage(domain), nil)
			t.Cleanup(func() { _ = keys.Close() })
			owner := glue.New(glue.Config{Repository: glue.NewMemoryRepository(domain), ConnectionCrypto: keys})
			t.Cleanup(func() { _ = owner.Close() })
			commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"glue": owner, "kms": keys})
			if encrypted {
				key, err := cfnComputeCall[kmsapi.CreateKeyOutput](ctx, commands, "kms", "CreateKey", map[string]any{})
				if err != nil {
					t.Fatal(err)
				}
				if err := cfnComputeRun(ctx, commands, "glue", "PutDataCatalogEncryptionSettings", map[string]any{"DataCatalogEncryptionSettings": map[string]any{"ConnectionPasswordEncryption": map[string]any{"ReturnConnectionPasswordEncrypted": true, "AwsKmsKeyId": *key.KeyMetadata.Arn}}}); err != nil {
					t.Fatal(err)
				}
			}
			h := cfnGlueConnection{commands}
			r := cfnAnalyticsTestRequest("AWS::Glue::Connection", cloudformation.Properties{"CatalogId": "123456789012", "ConnectionInput": map[string]any{"Name": "private-jdbc", "ConnectionType": "JDBC", "Description": "before", "ConnectionProperties": map[string]any{"JDBC_CONNECTION_URL": "jdbc:postgresql://localhost/catalog", "USERNAME": "reader", "PASSWORD": "retained-secret-sentinel"}}})
			created, err := h.Create(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			native := func() glueapi.ConnectionProperties {
				t.Helper()
				out, err := cfnComputeCall[glueapi.GetConnectionOutput](ctx, commands, "glue", "GetConnection", map[string]any{"Name": "private-jdbc"})
				if err != nil {
					t.Fatal(err)
				}
				return out.Connection.ConnectionProperties
			}
			before := native()
			if encrypted {
				if before["ENCRYPTED_PASSWORD"] == "" || before["PASSWORD"] != "" {
					t.Fatal("real KMS admission did not retain an encrypted password")
				}
			} else if before["PASSWORD"] != "retained-secret-sentinel" {
				t.Fatal("native admission did not retain the real password")
			}

			manual := clock.NewManual(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
			cc := cloudcontrol.New(cloudcontrol.Config{Clock: manual, Handlers: CloudFormationAnalyticsHandlers(commands)})
			t.Cleanup(func() { _ = cc.Close() })
			publicCommands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"cloudcontrol": cc})
			assertRedacted := func(raw string) cloudformation.Properties {
				t.Helper()
				if strings.Contains(raw, "PASSWORD") || strings.Contains(raw, "retained-secret-sentinel") || encrypted && strings.Contains(raw, string(before["ENCRYPTED_PASSWORD"])) {
					t.Fatal("public CloudControl model exposed a connection credential")
				}
				var p cloudformation.Properties
				if err := json.Unmarshal([]byte(raw), &p); err != nil {
					t.Fatal(err)
				}
				input, _ := cfnComputeObject(p["ConnectionInput"])
				properties, _ := cfnComputeObject(input["ConnectionProperties"])
				if properties["USERNAME"] != "reader" || properties["JDBC_CONNECTION_URL"] != "jdbc:postgresql://localhost/catalog" {
					t.Fatal("credential redaction removed nonsecret connection settings")
				}
				return p
			}
			listed, err := cfnComputeCall[ccapi.ListResourcesOutput](ctx, publicCommands, "cloudcontrol", "ListResources", map[string]any{"TypeName": r.Type})
			if err != nil || len(listed.ResourceDescriptions) != 1 {
				t.Fatalf("public list: %v, %v", listed, err)
			}
			assertRedacted(string(*listed.ResourceDescriptions[0].Properties))
			identifier := string(*listed.ResourceDescriptions[0].Identifier)
			get, err := cfnComputeCall[ccapi.GetResourceOutput](ctx, publicCommands, "cloudcontrol", "GetResource", map[string]any{"TypeName": r.Type, "Identifier": identifier})
			if err != nil {
				t.Fatal(err)
			}
			assertRedacted(string(*get.ResourceDescription.Properties))
			update, err := cfnComputeCall[ccapi.UpdateResourceOutput](ctx, publicCommands, "cloudcontrol", "UpdateResource", map[string]any{"TypeName": r.Type, "Identifier": identifier, "PatchDocument": `[{"op":"replace","path":"/ConnectionInput/Description","value":"after"}]`})
			if err != nil {
				t.Fatalf("nonsecret update admission: %v", err)
			}
			if _, err := cc.JobDriver().RunDue(ctx, 10); err != nil {
				t.Fatal(err)
			}
			status, err := cfnComputeCall[ccapi.GetResourceRequestStatusOutput](ctx, publicCommands, "cloudcontrol", "GetResourceRequestStatus", map[string]any{"RequestToken": update.ProgressEvent.RequestToken})
			if err != nil || cfnComputeValue(status.ProgressEvent.OperationStatus) != "SUCCESS" {
				t.Fatalf("nonsecret update completion: %v, %v", status, err)
			}
			after := native()
			if after["PASSWORD"] != before["PASSWORD"] || after["ENCRYPTED_PASSWORD"] != before["ENCRYPTED_PASSWORD"] {
				t.Fatal("read-derived nonsecret update changed the retained credential incarnation")
			}
			get, err = cfnComputeCall[ccapi.GetResourceOutput](ctx, publicCommands, "cloudcontrol", "GetResource", map[string]any{"TypeName": r.Type, "Identifier": identifier})
			if err != nil {
				t.Fatal(err)
			}
			model := assertRedacted(string(*get.ResourceDescription.Properties))
			input, _ := cfnComputeObject(model["ConnectionInput"])
			if input["Description"] != "after" {
				t.Fatal("nonsecret update did not reach the native connection")
			}
			if encrypted {
				if err := cfnComputeRun(ctx, commands, "glue", "PutDataCatalogEncryptionSettings", map[string]any{"DataCatalogEncryptionSettings": map[string]any{"ConnectionPasswordEncryption": map[string]any{"ReturnConnectionPasswordEncrypted": false}}}); err != nil {
					t.Fatal(err)
				}
				if native()["PASSWORD"] != "retained-secret-sentinel" {
					t.Fatal("retained ciphertext no longer decrypts to the admitted secret")
				}
			}

			// Explicit password writes and removals still converge. An invalid
			// removal must leave both the native secret and configuration intact.
			writable, err := cloudformation.WritableResourceProperties(r.Type, model)
			if err != nil {
				t.Fatal(err)
			}
			r.Previous = writable
			r.Properties, err = cloudformation.WritableResourceProperties(r.Type, model)
			if err != nil {
				t.Fatal(err)
			}
			input, _ = cfnComputeObject(r.Properties["ConnectionInput"])
			properties, _ := cfnComputeObject(input["ConnectionProperties"])
			properties["PASSWORD"] = "rotated-secret"
			if _, err := h.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			if native()["PASSWORD"] != "rotated-secret" {
				t.Fatal("explicit credential rotation did not reach the native owner")
			}
			r.Previous = r.Properties
			r.Properties, err = cloudformation.WritableResourceProperties(r.Type, model)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.Update(ctx, r); err == nil {
				t.Fatal("accepted removal of the only JDBC password")
			}
			if native()["PASSWORD"] != "rotated-secret" {
				t.Fatal("rejected removal changed the stored credential")
			}
			input, _ = cfnComputeObject(r.Properties["ConnectionInput"])
			properties, _ = cfnComputeObject(input["ConnectionProperties"])
			properties["SECRET_ID"] = "connection-credentials"
			if _, err := h.Update(ctx, r); err != nil {
				t.Fatalf("valid transition to secret authentication: %v", err)
			}
			if native()["PASSWORD"] != "" || native()["ENCRYPTED_PASSWORD"] != "" {
				t.Fatal("explicit valid password removal retained the secret")
			}
			removed := r.Properties
			r.Properties, r.Previous = r.Previous, removed
			if _, err := h.Update(ctx, r); err != nil {
				t.Fatalf("credential-removal rollback: %v", err)
			}
			if native()["PASSWORD"] != "rotated-secret" || native()["SECRET_ID"] != "" {
				t.Fatal("rollback did not restore the previous authentication configuration")
			}
		})
	}
}

// This fault reports a modeled error after the real repository commits the
// connection. It reproduces an uncertain native admission, not a fake resource.
type glueConnectionLostReplyRepository struct {
	glue.Repository
	loseReply bool
}

type glueConnectionAdmissionTx struct {
	glue.Transaction
	admitted *bool
}

func (t glueConnectionAdmissionTx) PutConnection(row glue.ConnectionRecord) error {
	if err := t.Transaction.PutConnection(row); err != nil {
		return err
	}
	*t.admitted = true
	return nil
}

func (r *glueConnectionLostReplyRepository) Attempt(ctx context.Context, fn func(glue.Transaction) error) error {
	admitted := false
	if err := r.Repository.Attempt(ctx, func(tx glue.Transaction) error {
		return fn(glueConnectionAdmissionTx{Transaction: tx, admitted: &admitted})
	}); err != nil {
		return err
	}
	if admitted && r.loseReply {
		r.loseReply = false
		return &awswire.Error{Code: "InternalServiceException", Message: "native admission response lost", StatusCode: 500}
	}
	return nil
}

func TestGlueConnectionUncertainCreateRetainsExactOwnedID(t *testing.T) {
	ctx := cfnAnalyticsTestContext()
	repository := &glueConnectionLostReplyRepository{Repository: glue.NewMemoryRepository(nil), loseReply: true}
	owner := glue.New(glue.Config{Repository: repository})
	t.Cleanup(func() { _ = owner.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"glue": owner})
	h := cfnGlueConnection{commands}
	r := cfnAnalyticsTestRequest("AWS::Glue::Connection", cloudformation.Properties{"CatalogId": "123456789012", "ConnectionInput": map[string]any{"Name": "uncertain-jdbc", "ConnectionType": "JDBC", "ConnectionProperties": map[string]any{"JDBC_CONNECTION_URL": "jdbc:postgresql://localhost/catalog", "USERNAME": "reader", "PASSWORD": "admitted-secret"}}})
	result, err := h.Create(ctx, r)
	if err == nil || result.PhysicalID != "123456789012|uncertain-jdbc" {
		t.Fatalf("lost admission reply did not return the authentic ID and error: %v, %v", result, err)
	}
	r.PhysicalID = result.PhysicalID
	out, err := cfnComputeCall[glueapi.GetConnectionOutput](ctx, commands, "glue", "GetConnection", map[string]any{"Name": "uncertain-jdbc"})
	if err != nil || out.Connection.ConnectionProperties["PASSWORD"] != "admitted-secret" {
		t.Fatalf("admitted native connection was not retained: %v, %v", out, err)
	}
	if replay, err := h.Create(ctx, r); err != nil || replay.PhysicalID != result.PhysicalID {
		t.Fatalf("same-incarnation replay did not recover admission: %v, %v", replay, err)
	}
	foreign := r
	foreign.Token = "foreign-incarnation"
	if replay, err := h.Create(ctx, foreign); err == nil || replay.PhysicalID != "" {
		t.Fatalf("foreign incarnation adopted an admitted connection: %v, %v", replay, err)
	}
	if err := h.Delete(ctx, foreign); err == nil {
		t.Fatal("foreign incarnation deleted the admitted connection")
	}
	if err := h.Delete(ctx, r); err != nil {
		t.Fatalf("exact-incarnation rollback: %v", err)
	}
	if _, err := h.Read(ctx, r); !cfnAnalyticsMissing(err) {
		t.Fatalf("rollback did not remove the admitted native connection: %v", err)
	}
}
