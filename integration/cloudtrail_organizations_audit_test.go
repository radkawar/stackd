package stackd_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/internal/awstest"
	orgprovider "stackd/internal/services/organizations"
	"stackd/journal"
	"stackd/storage"
)

func organizationsAuditClient(c cloudClients, account, region string) *cloudtrail.Client {
	return cloudtrail.New(cloudtrail.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestCloudTrailOrganizationsNativeDescribeSDK(t *testing.T) {
	var native map[string]any
	for _, row := range auditNativeRecords(t, "service_management_events") {
		if row["eventSource"] == "organizations.amazonaws.com" && row["eventName"] == "DescribeOrganization" {
			native = row
			break
		}
	}
	if native == nil {
		t.Fatal("missing native Organizations CloudTrail record")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "organizations.sqlite"))
			}
			guard := &organizationsAuditCAS{Storage: backends.Organizations}
			backends.Organizations = guard
			_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 13, 19, 2, 16, 0, time.UTC)))
			client := c.organizations(eventDeliveryAccount, "test")
			created, err := client.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
			if err != nil {
				t.Fatal(err)
			}
			// Reject every CAS to prove this read can publish history without a
			// pointless organization-state write or borrowing a read transaction.
			guard.reject.Store(true)
			result, err := awstest.CallSDK(t.Context(), client, "DescribeOrganization", []byte(`{}`))
			guard.reject.Store(false)
			if err != nil {
				t.Fatal(err)
			}
			requestID, _ := awsmiddleware.GetRequestIDMetadata(result.(*organizations.DescribeOrganizationOutput).ResultMetadata)
			got := auditLookupRecord(t, organizationsAuditClient(c, eventDeliveryAccount, "us-east-1"), requestID, "DescribeOrganization")
			for _, key := range []string{"eventSource", "eventName", "awsRegion", "requestParameters", "responseElements", "readOnly", "eventType", "managementEvent", "eventCategory"} {
				value, present := got[key]
				if !present || !reflect.DeepEqual(value, native[key]) {
					t.Fatalf("%s = %#v (present %v), native %#v", key, value, present, native[key])
				}
			}
			wantResource := native["resources"].([]any)[0].(map[string]any)
			resources, ok := got["resources"].([]any)
			if !ok || len(resources) != 1 {
				t.Fatalf("native organization resource lost: %#v", got)
			}
			resource := resources[0].(map[string]any)
			if len(resource) != len(wantResource) || resource["type"] != wantResource["type"] || resource["accountId"] != eventDeliveryAccount || resource["ARN"] != aws.ToString(created.Organization.Arn) || got["recipientAccountId"] != eventDeliveryAccount {
				t.Fatalf("organization identity/scope = %#v", got)
			}
			west, err := organizationsAuditClient(c, eventDeliveryAccount, "us-west-2").LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("DescribeOrganization")}}})
			if err != nil || len(west.Events) != 0 {
				t.Fatalf("global Organizations history appeared outside us-east-1: %+v %v", west, err)
			}
		})
	}
}

type organizationsAuditCAS struct {
	orgprovider.Storage
	conflict atomic.Bool
	reject   atomic.Bool
}

func (s *organizationsAuditCAS) CompareAndSwap(ctx context.Context, partition string, revision uint64, record orgprovider.PartitionRecord, effects func(context.Context) error) (bool, error) {
	if s.reject.Load() {
		return false, errors.New("unexpected organization write during read")
	}
	if s.conflict.Swap(false) {
		return s.Storage.CompareAndSwap(ctx, partition, revision+1, record, effects)
	}
	return s.Storage.CompareAndSwap(ctx, partition, revision, record, effects)
}

type organizationsAuditFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (s *organizationsAuditFailure) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := s.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "organizations.amazonaws.com" && call.EventName == "CreateOrganization" && call.ErrorCode == "" && s.fail.Swap(false) {
		return errors.New("injected failure after Organizations audit append")
	}
	return nil
}

func TestCloudTrailOrganizationsCASAuditAtomicitySDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "atomic.sqlite"))
			}
			failure := &organizationsAuditFailure{Storage: backends.Journal}
			backends.Journal = failure
			conflicts := &organizationsAuditCAS{Storage: backends.Organizations}
			backends.Organizations = conflicts
			_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 13, 19, 2, 16, 0, time.UTC)))
			client, trails := c.organizations(eventDeliveryAccount, "test"), organizationsAuditClient(c, eventDeliveryAccount, "us-east-1")
			failure.fail.Store(true)
			_, err := client.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
			assertAPIError(t, err, "ServiceException")
			var rejected interface{ ServiceRequestID() string }
			if !errors.As(err, &rejected) {
				t.Fatalf("missing failed request correlation: %v", err)
			}
			got := auditLookupRecord(t, trails, rejected.ServiceRequestID(), "CreateOrganization")
			if got["errorCode"] != "ServiceException" || got["responseElements"] != nil {
				t.Fatalf("rolled-back success leaked or independent error lost: %#v", got)
			}
			_, err = client.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
			assertAPIError(t, err, "AWSOrganizationsNotInUseException")
			_, err = c.iam(eventDeliveryAccount, "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(organizationsRoleName)})
			assertAPIError(t, err, "NoSuchEntity")
			conflicts.conflict.Store(true)
			created, err := client.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
			if err != nil {
				t.Fatal(err)
			}
			requestID, _ := awsmiddleware.GetRequestIDMetadata(created.ResultMetadata)
			got = auditLookupRecord(t, trails, requestID, "CreateOrganization")
			if got["errorCode"] != nil || got["responseElements"] == nil {
				t.Fatalf("CAS retry lost accepted API outcome: %#v", got)
			}
			rows, err := trails.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("CreateOrganization")}}})
			if err != nil || len(rows.Events) != 2 {
				t.Fatalf("CAS retry duplicated accepted API outcome: %+v %v", rows, err)
			}
		})
	}
}

func TestCloudTrailOrganizationsCommittedHandshakeErrorSDK(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 13, 19, 2, 16, 0, time.UTC))
	_, c, _ := startEventDeliveryCloud(t, storage.NewMemory(), source)
	sender := c.organizations(eventDeliveryAccount, "test")
	if _, err := sender.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	const email = "audit-member@example.test"
	created, err := sender.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("Audit member"), Email: aws.String(email)})
	if err != nil {
		t.Fatal(err)
	}
	status := waitAccountCreation(t, sender, created.CreateAccountStatus, source)
	if status.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("member creation failed: %+v", status)
	}
	recipient := aws.ToString(status.AccountId)
	member := c.organizations(recipient, "test")
	invited, err := sender.InviteAccountToOrganization(t.Context(), &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeEmail, Id: aws.String(email)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = member.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: invited.Handshake.Id})
	assertAPIError(t, err, "HandshakeConstraintViolationException")
	var rejected interface{ ServiceRequestID() string }
	if !errors.As(err, &rejected) {
		t.Fatalf("missing failed request correlation: %v", err)
	}
	described, err := member.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: invited.Handshake.Id})
	if err != nil || described.Handshake.State != orgtypes.HandshakeStateAccepted {
		t.Fatalf("committed modeled error lost native accepted transition: %+v %v", described, err)
	}
	got := auditLookupRecord(t, organizationsAuditClient(c, recipient, "us-east-1"), rejected.ServiceRequestID(), "AcceptHandshake")
	if got["errorCode"] != "HandshakeConstraintViolationException" || got["responseElements"] != nil || got["recipientAccountId"] != recipient {
		t.Fatalf("committed error missing or scoped to wrong account: %#v", got)
	}
	other, err := organizationsAuditClient(c, eventDeliveryAccount, "us-east-1").LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("AcceptHandshake")}}})
	if err != nil || len(other.Events) != 0 {
		t.Fatalf("member action leaked into management-account history: %+v %v", other, err)
	}
}
