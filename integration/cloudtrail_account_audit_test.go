package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"

	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
)

func TestCloudTrailAccountNativeAndDocumentedProjections(t *testing.T) {
	var native map[string]any
	for _, record := range auditNativeRecords(t, "service_management_events") {
		if record["eventSource"] == "account.amazonaws.com" && record["eventName"] == "GetRegionOptStatus" {
			native = record
			break
		}
	}
	if native == nil {
		t.Fatal("missing native Account capture")
	}
	body, err := os.ReadFile("../testdata/cloudtrail/audit/account.json")
	if err != nil {
		t.Fatal(err)
	}
	var documented struct {
		Observations []s3NativeObservation
		Events       []map[string]any
	}
	if err := json.Unmarshal(body, &documented); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "account-audit.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 13, 19, 2, 15, 0, time.UTC))
			_, c, _ := startEventDeliveryCloud(t, backends, source)
			client, trails := c.account(eventDeliveryAccount, "test", ""), trailNativeClient(c)
			check := func(row s3NativeObservation, want map[string]any) {
				t.Helper()
				_, requestID, err := s3NativeInvoke(t, client, row, nil)
				if err != nil {
					t.Fatal(err)
				}
				got := auditLookupRecord(t, trails, requestID, row.Operation)
				for _, field := range []string{"eventSource", "eventName", "awsRegion", "requestParameters", "responseElements", "readOnly", "eventType", "managementEvent", "eventCategory", "resources", "errorCode"} {
					expected, expectedPresent := want[field]
					actual, present := got[field]
					if present != expectedPresent || !reflect.DeepEqual(actual, expected) {
						t.Fatalf("%s %s: got %#v (present %v), native/documented %#v (present %v)", row.Operation, field, actual, present, expected, expectedPresent)
					}
				}
				if got["recipientAccountId"] != eventDeliveryAccount {
					t.Fatalf("Account outcome changed recipient: %#v", got)
				}
			}
			input, err := json.Marshal(native["requestParameters"])
			if err != nil {
				t.Fatal(err)
			}
			row := s3NativeObservation{Label: "native-get-region-opt-status", Operation: "GetRegionOptStatus", Input: input}
			row.Result.HTTPStatus = 200
			check(row, native)
			for _, kind := range []accounttypes.AlternateContactType{accounttypes.AlternateContactTypeSecurity, accounttypes.AlternateContactTypeOperations} {
				_, err := client.PutAlternateContact(t.Context(), &account.PutAlternateContactInput{AlternateContactType: kind, Name: aws.String("Owned Contact"), Title: aws.String("Operator"), EmailAddress: aws.String("owned@example.test"), PhoneNumber: aws.String("+1 202 555 0101")})
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, row := range documented.Observations {
				check(row, documented.Events[i])
			}
		})
	}
}

type accountAuditAppendFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (f *accountAuditAppendFailure) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := f.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "account.amazonaws.com" && call.EventName == "EnableRegion" && call.ErrorCode == "" && f.fail.Swap(false) {
		return errors.New("injected failure after Account audit append")
	}
	return nil
}

func TestCloudTrailAccountMutationRollbackAndDeniedTarget(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "account-rollback.sqlite"))
			}
			failure := &accountAuditAppendFailure{Storage: backends.Journal}
			backends.Journal = failure
			source := clock.NewManual(time.Date(2026, 9, 13, 19, 2, 15, 0, time.UTC))
			_, c, _ := startEventDeliveryCloud(t, backends, source)
			client := c.account(eventDeliveryAccount, "test", "")
			region := "af-south-1"
			failure.fail.Store(true)
			_, err := client.EnableRegion(t.Context(), &account.EnableRegionInput{RegionName: &region})
			assertAPIError(t, err, "InternalServerException")
			status, err := client.GetRegionOptStatus(t.Context(), &account.GetRegionOptStatusInput{RegionName: &region})
			if err != nil || status.RegionOptStatus != accounttypes.RegionOptStatusDisabled {
				t.Fatalf("audit append failure leaked region enable: %+v %v", status, err)
			}
			rows, err := backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			var failedRequest string
			for _, row := range rows {
				call := row.APICallCompleted
				if call == nil || call.EventSource != "account.amazonaws.com" || call.EventName != "EnableRegion" {
					continue
				}
				if call.ErrorCode == "" {
					t.Fatal("rolled-back region enable left successful audit history")
				}
				failedRequest = row.RequestID
			}
			got := auditLookupRecord(t, trailNativeClient(c), failedRequest, "EnableRegion")
			if got["errorCode"] != "InternalServerException" || got["readOnly"] != false {
				t.Fatalf("rolled-back mutation lost rejected outcome: %#v", got)
			}
			// An explicitly targeted standalone account is not an Organizations
			// management/delegated request, even when the caller is its own root.
			_, err = client.EnableRegion(t.Context(), &account.EnableRegionInput{AccountId: aws.String("111111111111"), RegionName: &region})
			assertAPIError(t, err, "AccessDeniedException")
			target := c.account("111111111111", "test", "")
			status, err = target.GetRegionOptStatus(t.Context(), &account.GetRegionOptStatusInput{RegionName: &region})
			if err != nil || status.RegionOptStatus != accounttypes.RegionOptStatusDisabled {
				t.Fatalf("denied cross-account mutation changed target: %+v %v", status, err)
			}
			accepted, err := client.EnableRegion(t.Context(), &account.EnableRegionInput{RegionName: &region})
			if err != nil {
				t.Fatal(err)
			}
			requestID, _ := awsmiddleware.GetRequestIDMetadata(accepted.ResultMetadata)
			got = auditLookupRecord(t, trailNativeClient(c), requestID, "EnableRegion")
			if _, rejected := got["errorCode"]; rejected {
				t.Fatalf("successful retry retained rejected outcome: %#v", got)
			}
		})
	}
}

func TestCloudTrailAccountGeneratedRejections(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 13, 19, 2, 15, 0, time.UTC))
	_, c, _ := startEventDeliveryCloud(t, storage.NewMemory(), source)
	client, trails := c.account(eventDeliveryAccount, "test", ""), trailNativeClient(c)
	// The SDK sends an invalid modeled AccountId; the authenticated gateway
	// rejects decoding, so no failed raw document may enter requestParameters.
	_, err := client.GetRegionOptStatus(t.Context(), &account.GetRegionOptStatusInput{AccountId: aws.String("invalid-id"), RegionName: aws.String("us-east-1")})
	assertAPIError(t, err, "ValidationException")
	var rejected interface{ ServiceRequestID() string }
	if !errors.As(err, &rejected) {
		t.Fatalf("missing rejected request correlation: %v", err)
	}
	got := auditLookupRecord(t, trails, rejected.ServiceRequestID(), "GetRegionOptStatus")
	if got["errorCode"] != "ValidationException" || got["requestParameters"] != nil || got["responseElements"] != nil || got["readOnly"] != true {
		t.Fatalf("gateway decode rejection leaked input or lost its outcome: %#v", got)
	}
	// This operation is generated and known, but not implemented by Account.
	// It must retain the actual error, never produce a successful native event.
	_, err = client.GetGovCloudAccountInformation(t.Context(), &account.GetGovCloudAccountInformationInput{})
	assertAPIError(t, err, "UnknownOperationException")
	if !errors.As(err, &rejected) {
		t.Fatalf("missing unsupported request correlation: %v", err)
	}
	got = auditLookupRecord(t, trails, rejected.ServiceRequestID(), "GetGovCloudAccountInformation")
	if got["errorCode"] != "UnknownOperationException" || got["responseElements"] != nil || got["readOnly"] != true {
		t.Fatalf("unsupported operation produced a fake success: %#v", got)
	}
}
