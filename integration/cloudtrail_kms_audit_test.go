package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go/middleware"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awstest"
	kmsservice "stackd/internal/services/kms"
	"stackd/journal"
	"stackd/storage"
)

func TestCloudTrailKMSNativeProjections(t *testing.T) {
	native := auditNativeRecords(t, "service_management_events")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "kms-native.sqlite"))
			}
			epoch := time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC)
			_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(epoch))
			client, trails := c.kms(eventDeliveryAccount, "test", ""), trailNativeClient(c)
			symmetric, err := client.CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			rsa, err := client.CreateKey(t.Context(), &kms.CreateKeyInput{KeySpec: types.KeySpecRsa4096, KeyUsage: types.KeyUsageTypeEncryptDecrypt})
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, err := client.Encrypt(t.Context(), &kms.EncryptInput{KeyId: symmetric.KeyMetadata.KeyId, Plaintext: []byte("kms-audit-private-plaintext")})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"Encrypt", "Decrypt", "DescribeKey", "DisableKey", "ScheduleKeyDeletion"} {
				t.Run(name, func(t *testing.T) {
					var expected map[string]any
					for _, record := range native {
						if record["eventSource"] == "kms.amazonaws.com" && record["eventName"] == name && record["errorCode"] == nil {
							expected = record
							break
						}
					}
					if expected == nil {
						t.Fatalf("missing native successful %s", name)
					}
					key := symmetric.KeyMetadata
					if name == "Encrypt" {
						key = rsa.KeyMetadata
					}
					resources := expected["resources"].([]any)
					oldARN := resources[0].(map[string]any)["ARN"].(string)
					oldID := oldARN[strings.LastIndex(oldARN, "/")+1:]
					encoded, err := json.Marshal(expected)
					if err != nil {
						t.Fatal(err)
					}
					text := strings.ReplaceAll(string(encoded), oldARN, aws.ToString(key.Arn))
					text = strings.ReplaceAll(text, oldID, aws.ToString(key.KeyId))
					text = strings.ReplaceAll(text, "000000000000", eventDeliveryAccount)
					var want map[string]any
					if err := json.Unmarshal([]byte(text), &want); err != nil {
						t.Fatal(err)
					}
					if name == "ScheduleKeyDeletion" {
						want["responseElements"].(map[string]any)["deletionDate"] = epoch.Add(7 * 24 * time.Hour).Format(time.RFC3339)
					}
					input, err := json.Marshal(want["requestParameters"])
					if err != nil {
						t.Fatal(err)
					}
					result, err := awstest.CallSDK(t.Context(), client, name, input, func(value any) {
						switch in := value.(type) {
						case *kms.EncryptInput:
							in.Plaintext = []byte("kms-audit-private-plaintext")
						case *kms.DecryptInput:
							in.CiphertextBlob = ciphertext.CiphertextBlob
						}
					})
					if err != nil {
						t.Fatal(err)
					}
					metadata := reflect.ValueOf(result).Elem().FieldByName("ResultMetadata").Interface().(middleware.Metadata)
					requestID, ok := awsmiddleware.GetRequestIDMetadata(metadata)
					if !ok || requestID == "" {
						t.Fatal("SDK response has no request correlation")
					}
					got := auditLookupRecord(t, trails, requestID, name)
					for _, field := range []string{"eventSource", "eventName", "readOnly", "managementEvent", "eventCategory", "requestParameters", "responseElements", "resources"} {
						if !reflect.DeepEqual(got[field], want[field]) {
							t.Fatalf("%s: got %#v; native %#v", field, got[field], want[field])
						}
					}
				})
			}
		})
	}
}

type kmsAuditAppendFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (f *kmsAuditAppendFailure) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := f.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "kms.amazonaws.com" && call.EventName == "DisableKey" && call.ErrorCode == "" && f.fail.Swap(false) {
		return errors.New("injected failure after real KMS audit append")
	}
	return nil
}

func TestCloudTrailKMSAuditRollbackAndDryRun(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "kms-rollback.sqlite"))
			}
			failing := &kmsAuditAppendFailure{Storage: backends.Journal}
			backends.Journal = failing
			_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC)))
			client := c.kms(eventDeliveryAccount, "test", "")
			key, err := client.CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			failing.fail.Store(true)
			_, err = client.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: key.KeyMetadata.KeyId})
			assertAPIError(t, err, "KMSInternalException")
			out, err := client.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.KeyId})
			if err != nil || !out.KeyMetadata.Enabled {
				t.Fatalf("failed audit committed key disable: %+v %v", out, err)
			}
			_, err = client.Encrypt(t.Context(), &kms.EncryptInput{KeyId: key.KeyMetadata.KeyId, Plaintext: []byte("never-record-this-plaintext"), DryRun: aws.Bool(true)})
			assertAPIError(t, err, "DryRunOperationException")
			rows, err := backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			disabled, dryRuns := 0, 0
			for _, row := range rows {
				call := row.APICallCompleted
				if call == nil || call.EventSource != "kms.amazonaws.com" {
					continue
				}
				switch call.EventName {
				case "DisableKey":
					disabled++
					if call.ErrorCode != "KMSInternalException" {
						t.Fatalf("rolled back disable published success: %+v", call)
					}
				case "Encrypt":
					dryRuns++
					if call.ErrorCode != "DryRunOperationException" || !call.ReadOnly || call.Category != journal.CategoryManagement {
						t.Fatalf("incorrect dry-run outcome: %+v", call)
					}
				}
			}
			if disabled != 1 || dryRuns != 1 {
				t.Fatalf("duplicate/missing outcomes: disable=%d dryRun=%d", disabled, dryRuns)
			}
			if strings.Contains(journalJSON(t, rows), "never-record-this-plaintext") {
				t.Fatal("cryptographic plaintext leaked")
			}
		})
	}
}

func TestCloudTrailKMSInternalCommandsUseKMSInputs(t *testing.T) {
	backends := storage.NewMemory()
	service := kmsservice.NewWithConfig(kmsservice.Config{Storage: backends.KMS, APIEvents: apievents.New(backends.Journal)})
	t.Cleanup(func() { _ = service.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: eventDeliveryAccount, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + eventDeliveryAccount + ":root", PrincipalID: eventDeliveryAccount, RequestID: "internal-kms"})
	// Internal KMS calls inherit trusted identity, not the parent generated input.
	decoded, err := sqsapi.DecodeRequest("SendMessage", awsapi.Request{JSON: []byte(`{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/111111111111/parent","MessageBody":"private-parent-body"}`)})
	if err != nil {
		t.Fatal(err)
	}
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	arn, apiErr := service.EnsureServiceKey(ctx, "sqs")
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	if same, err := service.EnsureServiceKey(ctx, "sqs"); err != nil || same != arn {
		t.Fatalf("managed key reuse: %q %v", same, err)
	}
	// The Encrypt failure itself is an outcome and must preserve its generated
	// KMS input, not the inherited SendMessage DTO or secret body.
	_, _, apiErr = service.Encrypt(ctx, arn, []byte("private-crypto-input"), map[string]string{"purpose": "audit"})
	if apiErr == nil {
		t.Fatal("managed key unexpectedly permitted a non-forwarded root call")
	}
	forwarded := kmsservice.WithViaService(ctx, "sqs")
	encrypted, _, apiErr := service.Encrypt(forwarded, arn, []byte("private-crypto-input"), map[string]string{"purpose": "audit"})
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	plaintext, _, apiErr := service.Decrypt(forwarded, encrypted, map[string]string{"purpose": "audit"})
	if apiErr != nil || string(plaintext) != "private-crypto-input" {
		t.Fatalf("internal decryption: %q %v", plaintext, apiErr)
	}
	dataKey, encryptedKey, _, apiErr := service.GenerateDataKey(forwarded, arn, map[string]string{"purpose": "audit"})
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	recoveredKey, _, apiErr := service.Decrypt(forwarded, encryptedKey, map[string]string{"purpose": "audit"})
	if apiErr != nil || !reflect.DeepEqual(recoveredKey, dataKey) {
		t.Fatalf("internal data-key decryption: %v", apiErr)
	}
	rows, err := backends.Journal.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, row := range rows {
		call := row.APICallCompleted
		if call == nil {
			continue
		}
		counts[call.EventName]++
		if call.EventSource != "kms.amazonaws.com" || call.Category != journal.CategoryManagement {
			t.Fatalf("inherited parent classification: %+v", call)
		}
		if call.EventName == "Encrypt" {
			var request map[string]any
			if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
				t.Fatal(err)
			}
			if request["keyId"] != arn || request["encryptionAlgorithm"] != "SYMMETRIC_DEFAULT" || request["queueUrl"] != nil {
				t.Fatalf("wrong internal generated input: %#v", request)
			}
		}
	}
	if !reflect.DeepEqual(counts, map[string]int{"CreateKey": 1, "CreateAlias": 1, "Encrypt": 2, "Decrypt": 2, "GenerateDataKey": 1}) {
		t.Fatalf("internal command outcomes: %#v", counts)
	}
	body := journalJSON(t, rows)
	if strings.Contains(body, "private-parent-body") || strings.Contains(body, "private-crypto-input") {
		t.Fatal("inherited or cryptographic secret leaked")
	}
}

func TestCloudTrailKMSRejectedGeneratedRequests(t *testing.T) {
	backends := storage.NewMemory()
	service := kmsservice.NewWithConfig(kmsservice.Config{Storage: backends.KMS, APIEvents: apievents.New(backends.Journal)})
	t.Cleanup(func() { _ = service.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: eventDeliveryAccount, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + eventDeliveryAccount + ":root", PrincipalID: eventDeliveryAccount})
	for _, request := range []struct{ name, body string }{
		{"DescribeKey", `{"KeyId":"alias/missing"}`},
		{"Encrypt", `{"Plaintext":"private-malformed-crypto-body"}`},
		{"NotAKMSOperation", `{"secret":"private-unknown-body"}`},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(request.body)).WithContext(ctx)
		r.Header.Set("X-Amz-Target", "TrentService."+request.name)
		w := httptest.NewRecorder()
		service.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s rejected status %d", request.name, w.Code)
		}
	}
	rows, err := backends.Journal.Read(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var calls []journal.APICallCompleted
	for _, row := range rows {
		if row.APICallCompleted != nil {
			calls = append(calls, *row.APICallCompleted)
		}
	}
	if len(calls) != 2 {
		t.Fatalf("known rejection count: %d", len(calls))
	}
	nativeCode := ""
	for _, record := range auditNativeRecords(t, "service_management_events") {
		if record["eventSource"] == "kms.amazonaws.com" && record["eventName"] == "DescribeKey" && record["errorCode"] == "NotFoundException" {
			nativeCode = record["errorCode"].(string)
			if record["requestParameters"] != nil || record["responseElements"] != nil {
				t.Fatal("native missing-key expectation changed")
			}
			break
		}
	}
	if nativeCode == "" || calls[0].ErrorCode != nativeCode || calls[1].ErrorCode != "ValidationException" {
		t.Fatalf("rejection outcomes: %+v", calls)
	}
	for _, call := range calls {
		if len(call.RequestParameters) != 0 && string(call.RequestParameters) != "null" || len(call.ResponseElements) != 0 || len(call.EventResources) != 0 {
			t.Fatalf("failed decoding or missing alias leaked request/resources: %+v", call)
		}
	}
	if strings.Contains(journalJSON(t, rows), "private-") {
		t.Fatal("failed raw body leaked into audit")
	}
}

func TestCloudTrailKMSNestedIAMRejectionSurvivesRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "kms-iam-rejection.sqlite"))
			}
			_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC)))
			_, access, secret := c.user(t, eventDeliveryAccount, "kms-only-creator")
			root := c.iam(eventDeliveryAccount, "test", "")
			putUserPolicy(t, root, "kms-only-creator", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:CreateKey","Resource":"*"}]}`)
			client := c.kms(access, secret, "")
			_, err := client.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
			assertAPIError(t, err, "AccessDeniedException")
			keys, err := c.kms(eventDeliveryAccount, "test", "").ListKeys(t.Context(), &kms.ListKeysInput{})
			if err != nil || len(keys.Keys) != 0 {
				t.Fatalf("denied nested IAM creation published a KMS key: %+v %v", keys, err)
			}
			_, err = root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(kmsservice.MultiRegionServiceRoleName)})
			assertAPIError(t, err, "NoSuchEntity")
			rows, err := backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			kmsFailures, iamFailures := 0, 0
			for _, row := range rows {
				call := row.APICallCompleted
				if call == nil {
					continue
				}
				if call.EventSource == "kms.amazonaws.com" && call.EventName == "CreateKey" {
					kmsFailures++
					if call.ErrorCode != "AccessDeniedException" {
						t.Fatalf("incorrect parent failure: %+v", call)
					}
				}
				if call.EventSource == "iam.amazonaws.com" && call.EventName == "CreateServiceLinkedRole" {
					iamFailures++
					if call.ErrorCode == "" {
						t.Fatalf("denied child published success: %+v", call)
					}
					var request map[string]any
					if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
						t.Fatal(err)
					}
					if request != nil {
						t.Fatalf("denied IAM child exposed request parameters: %#v", request)
					}
				}
			}
			if kmsFailures != 1 || iamFailures != 1 {
				t.Fatalf("rollback lost or duplicated rejection: kms=%d iam=%d", kmsFailures, iamFailures)
			}
		})
	}
}

func TestCloudTrailKMSCrossAccountSuccessAndDenialScopes(t *testing.T) {
	backends := storage.NewMemory()
	_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC)))
	const callerAccount = "222222222222"
	callerARN, access, secret := c.user(t, callerAccount, "cross-account-kms-audit")
	putUserPolicy(t, c.iam(callerAccount, "test", ""), "cross-account-kms-audit", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:Encrypt","Resource":"*"}]}`)
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + eventDeliveryAccount + `:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"AWS":"` + callerARN + `"},"Action":"kms:Encrypt","Resource":"*"}]}`
	key, err := c.kms(eventDeliveryAccount, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{Policy: &policy})
	if err != nil {
		t.Fatal(err)
	}
	input := &kms.EncryptInput{KeyId: key.KeyMetadata.Arn, Plaintext: []byte("cross-account-private-input")}
	if _, err := c.kms(access, secret, "").Encrypt(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	putUserPolicy(t, c.iam(callerAccount, "test", ""), "cross-account-kms-audit", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"kms:Encrypt","Resource":"*"}]}`)
	_, err = c.kms(access, secret, "").Encrypt(t.Context(), input)
	assertAPIError(t, err, "AccessDeniedException")
	rows, err := backends.Journal.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	shared, ownerSuccess, callerSuccess, denied := "", 0, 0, 0
	for _, row := range rows {
		call := row.APICallCompleted
		if call == nil || call.EventSource != "kms.amazonaws.com" || call.EventName != "Encrypt" {
			continue
		}
		if call.ErrorCode != "" {
			denied++
			if row.AccountID != callerAccount || call.SharedEventID != "" {
				t.Fatalf("denial leaked to key-owner history: %+v", row)
			}
			continue
		}
		if call.SharedEventID == "" || shared != "" && shared != call.SharedEventID {
			t.Fatal("cross-account records lack shared correlation")
		}
		shared = call.SharedEventID
		switch row.AccountID {
		case callerAccount:
			callerSuccess++
		case eventDeliveryAccount:
			ownerSuccess++
		default:
			t.Fatalf("unexpected audit recipient %q", row.AccountID)
		}
	}
	if callerSuccess != 1 || ownerSuccess != 1 || denied != 1 {
		t.Fatalf("cross-account outcomes: caller=%d owner=%d denied=%d", callerSuccess, ownerSuccess, denied)
	}
}
