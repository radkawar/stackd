package guardduty

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
	"stackd/storage/memory"
)

// Isolate admission and commit races here; integration exercises real S3/KMS.
type destinationControlSink struct {
	validate func(context.Context, PublishingDestination) error
}

func (s *destinationControlSink) Validate(ctx context.Context, v PublishingDestination) error {
	if s.validate != nil {
		return s.validate(ctx, v)
	}
	return nil
}
func (*destinationControlSink) Export(context.Context, PublishingDestination, string, []byte) error {
	return errors.New("unexpected export in control-plane test")
}

type destinationControlFixture struct {
	s      *Service
	ctx    context.Context
	d      Detector
	sink   *destinationControlSink
	auth   *filterTestAuthorizer
	events journal.Storage
}

func newDestinationControlFixture(t *testing.T) destinationControlFixture {
	t.Helper()
	domain := memory.NewDomain()
	events := journal.NewMemory(domain)
	auth := &filterTestAuthorizer{}
	sink := &destinationControlSink{}
	s := New(Config{Repository: NewMemoryRepository(domain), Authorizer: auth, Recorder: apievents.New(events), Clock: clock.NewManual(time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC))})
	s.destinationSink = sink
	t.Cleanup(func() { _ = s.Close() })
	d := Detector{Scope: Scope{"aws", "123456789012", "us-east-1"}, ID: "0123456789abcdef0123456789abcdef", Status: "ENABLED", Frequency: "ONE_HOUR"}
	d.ARN = detectorARN(d.Scope, d.ID)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: d.Partition, AccountID: d.AccountID, Region: d.Region, PrincipalARN: "arn:aws:iam::123456789012:user/destination-owner", RequestID: "destination-request", SourceIP: "192.0.2.9"})
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDetector(d) }); err != nil {
		t.Fatal(err)
	}
	return destinationControlFixture{s, ctx, d, sink, auth, events}
}

func (h destinationControlFixture) input() *api.CreatePublishingDestinationRequest {
	return &api.CreatePublishingDestinationRequest{DetectorId: new(api.DetectorId(h.d.ID)), DestinationType: new(api.DestinationTypeS3), ClientToken: new(api.ClientToken("destination-token")), Tags: api.TagMap{"team": "blue"}, DestinationProperties: &api.DestinationProperties{DestinationArn: new(api.String("arn:aws:s3:::owned")), KmsKeyArn: new(api.String("arn:aws:kms:us-east-1:123456789012:key/owned"))}}
}
func (h destinationControlFixture) create(t *testing.T) string {
	t.Helper()
	out, err := filterCall(h.s, h.ctx, "CreatePublishingDestination", h.input())
	if err != nil {
		t.Fatal(err)
	}
	return value(out.(*api.CreatePublishingDestinationResponse).DestinationId)
}
func (h destinationControlFixture) update(id string, p *api.DestinationProperties) *awswire.Error {
	_, err := filterCall(h.s, h.ctx, "UpdatePublishingDestination", &api.UpdatePublishingDestinationRequest{DetectorId: new(api.DetectorId(h.d.ID)), DestinationId: new(api.String(id)), DestinationProperties: p})
	return err
}
func (h destinationControlFixture) remove(id string) *awswire.Error {
	_, err := filterCall(h.s, h.ctx, "DeletePublishingDestination", &api.DeletePublishingDestinationRequest{DetectorId: new(api.DetectorId(h.d.ID)), DestinationId: new(api.String(id))})
	return err
}
func (h destinationControlFixture) destination(t *testing.T, id string) PublishingDestination {
	t.Helper()
	var v PublishingDestination
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		var err error
		v, err = r.PublishingDestination(h.d.Scope, h.d.ID, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return v
}
func (h destinationControlFixture) requireAbsent(t *testing.T) {
	t.Helper()
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		all, err := r.PublishingDestinations(h.d.Scope, h.d.ID)
		if len(all) != 0 {
			t.Fatalf("rejected create left destinations: %+v", all)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPublishingDestinationValidationRollbackAndActualOutcome(t *testing.T) {
	h := newDestinationControlFixture(t)
	h.sink.validate = func(ctx context.Context, v PublishingDestination) error {
		if apievents.EventID(ctx) == "" {
			t.Fatal("external validation has no reserved API outcome")
		}
		probe, cancel := context.WithTimeout(h.ctx, time.Second)
		defer cancel()
		if err := h.s.repository.View(probe, func(r Reader) error {
			_, err := r.PublishingDestination(v.Scope, v.DetectorID, v.ID)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("destination accepted before sink validation: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return invalid("sink denied")
	}
	if _, err := filterCall(h.s, h.ctx, "CreatePublishingDestination", h.input()); err == nil || err.StatusCode != 400 {
		t.Fatalf("validation failure: %v", err)
	}
	h.requireAbsent(t)
	rows, err := h.events.Read(h.ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].APICallCompleted.ErrorCode != "BadRequestException" || rows[0].ActorARN != awsctx.FromContext(h.ctx).PrincipalARN || rows[0].RequestID != "destination-request" {
		t.Fatalf("validation recorded the wrong outcome: %+v", rows)
	}
	h.sink.validate = nil
	id := h.create(t)
	before := h.destination(t, id)
	h.sink.validate = func(context.Context, PublishingDestination) error { return invalid("sink denied") }
	if err := h.update(id, &api.DestinationProperties{KmsKeyArn: new(api.String("arn:aws:kms:us-east-1:123456789012:key/replacement"))}); err == nil {
		t.Fatal("denied replacement succeeded")
	}
	if got := h.destination(t, id); !reflect.DeepEqual(got, before) {
		t.Fatalf("validation failure changed accepted metadata: %+v", got)
	}
	h.s.destinationSink = nil
	if err := h.update(id, &api.DestinationProperties{DestinationArn: new(api.String("arn:aws:s3:::replacement"))}); err == nil || err.StatusCode != 500 {
		t.Fatalf("unavailable sink was treated as validation: %v", err)
	}
	if got := h.destination(t, id); !reflect.DeepEqual(got, before) {
		t.Fatal("unavailable sink changed destination")
	}
}

func TestPublishingDestinationReplayValidatesWithoutApplyingChanges(t *testing.T) {
	h := newDestinationControlFixture(t)
	id := h.create(t)
	before := h.destination(t, id)
	in := h.input()
	in.Tags["changed"] = "yes"
	in.DestinationProperties.DestinationArn = new(api.String("arn:aws:s3:::owned/existing-prefix"))
	out, err := filterCall(h.s, h.ctx, "CreatePublishingDestination", in)
	if err != nil || value(out.(*api.CreatePublishingDestinationResponse).DestinationId) != id {
		t.Fatalf("valid changed replay: %v, %v", out, err)
	}
	if got := h.destination(t, id); !reflect.DeepEqual(got, before) {
		t.Fatal("replay applied changed properties or tags")
	}
	h.sink.validate = func(context.Context, PublishingDestination) error { return invalid("prefix missing") }
	if _, err := filterCall(h.s, h.ctx, "CreatePublishingDestination", in); err == nil || err.StatusCode != 400 {
		t.Fatalf("replay bypassed current sink validation: %v", err)
	}
	h.sink.validate = nil
	in.ClientToken = new(api.ClientToken("different-token"))
	if _, err := filterCall(h.s, h.ctx, "CreatePublishingDestination", in); err == nil || err.StatusCode != 400 {
		t.Fatalf("second S3 destination exceeded quota: %v", err)
	}
	if got := h.destination(t, id); !reflect.DeepEqual(got, before) {
		t.Fatal("failed replay or quota rejection changed original")
	}
}

func TestPublishingDestinationUpdateHealthAndExportCutover(t *testing.T) {
	h := newDestinationControlFixture(t)
	now := h.s.clock.Now()
	active := Finding{Scope: h.d.Scope, DetectorID: h.d.ID, ID: "active", Created: now, Updated: now, Count: 1, Observation: Observation{Type: "Policy:IAMUser/RootCredentialUsage", ResourceType: "AccessKey", UserType: "Root", API: "ListBuckets", ServiceName: "s3.amazonaws.com"}}
	archived := active
	archived.ID, archived.Archived = "archived", true
	if err := h.s.repository.Update(h.ctx, func(tx Transaction) error {
		if err := tx.PutFinding(active); err != nil {
			return err
		}
		return tx.PutFinding(archived)
	}); err != nil {
		t.Fatal(err)
	}
	id := h.create(t)
	before := h.destination(t, id)
	if before.Status != "PUBLISHING" || before.Version != 1 || !before.FailureStarted.IsZero() {
		t.Fatalf("create did not enter healthy publishing: %+v", before)
	}
	var first FindingExport
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		var err error
		first, err = r.FindingExport(h.d.Scope, h.d.ID, id, active.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if first.DestinationVersion != before.Version || !first.Due.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("existing active finding not scheduled for new destination: %+v", first)
	}
	if err := h.s.repository.Update(h.ctx, func(tx Transaction) error {
		before.Status, before.FailureStarted = "UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY", now.Add(-time.Hour)
		if err := tx.PutPublishingDestination(before); err != nil {
			return err
		}
		return tx.PutFindingExport(FindingExport{Scope: h.d.Scope, DetectorID: h.d.ID, DestinationID: id, FindingID: archived.ID, ID: "stale", DestinationVersion: before.Version, Due: now})
	}); err != nil {
		t.Fatal(err)
	}
	failed, err := filterCall(h.s, h.ctx, "DescribePublishingDestination", &api.DescribePublishingDestinationRequest{DetectorId: new(api.DetectorId(h.d.ID)), DestinationId: new(api.String(id))})
	if err != nil {
		t.Fatal(err)
	}
	if got := failed.(*api.DescribePublishingDestinationResponse).PublishingFailureStartTimestamp; got == nil || int64(*got) != before.FailureStarted.UnixMilli() {
		t.Fatalf("failure timestamp is not epoch milliseconds: %v", got)
	}
	newKey := "arn:aws:kms:us-east-1:123456789012:key/new"
	if err := h.update(id, &api.DestinationProperties{KmsKeyArn: new(api.String(newKey))}); err != nil {
		t.Fatal(err)
	}
	updated := h.destination(t, id)
	if updated.DestinationARN != before.DestinationARN || updated.KMSKeyARN != newKey || updated.Version != before.Version+1 || updated.Status != "PUBLISHING" || !updated.FailureStarted.IsZero() {
		t.Fatalf("key-only update lost properties or health transition: %+v", updated)
	}
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		exports, err := r.FindingExports(h.d.Scope, h.d.ID, id)
		if len(exports) != 1 || exports[0].FindingID != active.ID || exports[0].DestinationVersion != updated.Version || exports[0].ID == first.ID {
			t.Fatalf("cutover retained stale work or queued archived finding: %+v", exports)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.update(id, &api.DestinationProperties{DestinationArn: new(api.String("arn:aws:s3:::new"))}); err != nil {
		t.Fatal(err)
	}
	out, err := filterCall(h.s, h.ctx, "DescribePublishingDestination", &api.DescribePublishingDestinationRequest{DetectorId: new(api.DetectorId(h.d.ID)), DestinationId: new(api.String(id))})
	if err != nil {
		t.Fatal(err)
	}
	described := out.(*api.DescribePublishingDestinationResponse)
	if value(described.DestinationId) != id || value(described.DestinationType) != "S3" || value(described.Status) != "PUBLISHING" || described.PublishingFailureStartTimestamp != nil || value(described.DestinationProperties.KmsKeyArn) != newKey || value(described.DestinationProperties.DestinationArn) != "arn:aws:s3:::new" || described.Tags["team"] != "blue" {
		t.Fatalf("describe lost modeled destination state: %+v", described)
	}
	if err := h.remove(id); err != nil {
		t.Fatal(err)
	}
	h.requireAbsent(t)
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		exports, err := r.FindingExports(h.d.Scope, h.d.ID, id)
		if len(exports) != 0 {
			t.Fatalf("delete retained export work: %+v", exports)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.remove(id); err == nil || err.StatusCode != 400 {
		t.Fatalf("repeat delete should reject missing destination: %v", err)
	}
}

func TestPublishingDestinationUpdateFencesConcurrentMutation(t *testing.T) {
	for _, mutation := range []string{"update", "delete", "tags"} {
		t.Run(mutation, func(t *testing.T) {
			h := newDestinationControlFixture(t)
			id := h.create(t)
			h.sink.validate = func(context.Context, PublishingDestination) error {
				// The second operation completes while the first is validating.
				h.sink.validate = nil
				var rejected *awswire.Error
				switch mutation {
				case "update":
					rejected = h.update(id, &api.DestinationProperties{KmsKeyArn: new(api.String("arn:aws:kms:us-east-1:123456789012:key/winner"))})
				case "delete":
					rejected = h.remove(id)
				default:
					_, rejected = filterCall(h.s, h.ctx, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.GuardDutyArn(publishingDestinationARN(h.d.Scope, h.d.ID, id))), Tags: api.TagMap{"team": "green"}})
				}
				if rejected != nil {
					return rejected
				}
				return nil
			}
			err := h.update(id, &api.DestinationProperties{DestinationArn: new(api.String("arn:aws:s3:::loser"))})
			if mutation == "tags" {
				if err != nil {
					t.Fatal(err)
				}
				v := h.destination(t, id)
				if v.Tags["team"] != "green" || v.DestinationARN != "arn:aws:s3:::loser" {
					t.Fatalf("update lost concurrent tags: %+v", v)
				}
				return
			}
			if err == nil {
				t.Fatal("stale validation was committed")
			}
			if mutation == "delete" {
				h.requireAbsent(t)
			} else if v := h.destination(t, id); v.KMSKeyARN != "arn:aws:kms:us-east-1:123456789012:key/winner" || v.DestinationARN != "arn:aws:s3:::owned" || v.Version != 2 {
				t.Fatalf("stale update replaced winner: %+v", v)
			}
		})
	}
}

func TestPublishingDestinationCurrentIAMAndRequestedTags(t *testing.T) {
	h := newDestinationControlFixture(t)
	h.auth.check = func(r authorization.Request) *awswire.Error {
		if r.Action == "guardduty:TagResource" && len(r.Context["aws:RequestTag/team"]) > 0 {
			return failure("AccessDeniedException", "tag-on-create denied", 403)
		}
		return nil
	}
	if _, err := filterCall(h.s, h.ctx, "CreatePublishingDestination", h.input()); err == nil || err.StatusCode != 403 {
		t.Fatalf("requested tags bypassed admission: %v", err)
	}
	h.requireAbsent(t)
	h.auth.check = nil
	id := h.create(t)
	arn := publishingDestinationARN(h.d.Scope, h.d.ID, id)
	h.auth.check = func(r authorization.Request) *awswire.Error {
		if (r.ResourceARN == arn || r.Action == "guardduty:CreatePublishingDestination") && r.Action != "guardduty:TagResource" && r.Action != "guardduty:ListTagsForResource" && !reflect.DeepEqual(r.Context["aws:ResourceTag/team"], []string{"blue"}) {
			return failure("AccessDeniedException", "current resource tag denied", 403)
		}
		return nil
	}
	h.sink.validate = func(context.Context, PublishingDestination) error {
		_, err := filterCall(h.s, h.ctx, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.GuardDutyArn(arn)), Tags: api.TagMap{"team": "revoked"}})
		if err != nil {
			return err
		}
		return nil
	}
	if err := h.update(id, &api.DestinationProperties{DestinationArn: new(api.String("arn:aws:s3:::denied"))}); err == nil || err.StatusCode != 403 {
		t.Fatalf("final commit ignored current IAM: %v", err)
	}
	if v := h.destination(t, id); v.DestinationARN != "arn:aws:s3:::owned" || v.Tags["team"] != "revoked" || v.Version != 1 {
		t.Fatalf("denied commit changed configuration or lost revoke: %+v", v)
	}
	for _, op := range []string{"DescribePublishingDestination", "DeletePublishingDestination", "CreatePublishingDestination"} {
		var in any = &api.DescribePublishingDestinationRequest{DetectorId: new(api.DetectorId(h.d.ID)), DestinationId: new(api.String(id))}
		if op == "DeletePublishingDestination" {
			in = &api.DeletePublishingDestinationRequest{DetectorId: new(api.DetectorId(h.d.ID)), DestinationId: new(api.String(id))}
		} else if op == "CreatePublishingDestination" {
			in = h.input()
		}
		if _, err := filterCall(h.s, h.ctx, op, in); err == nil || err.StatusCode != 403 {
			t.Fatalf("%s ignored revoked resource tag: %v", op, err)
		}
	}
	out, err := filterCall(h.s, h.ctx, "ListTagsForResource", &api.ListTagsForResourceRequest{ResourceArn: new(api.GuardDutyArn(arn))})
	if err != nil || out.(*api.ListTagsForResourceResponse).Tags["team"] != "revoked" {
		t.Fatalf("canonical lowercase ARN did not expose current tags: %v, %v", out, err)
	}
	if _, err := filterCall(h.s, h.ctx, "ListTagsForResource", &api.ListTagsForResourceRequest{ResourceArn: new(api.GuardDutyArn(strings.Replace(arn, "/publishingdestination/", "/publishingDestination/", 1)))}); err == nil {
		t.Fatal("noncanonical destination ARN accepted")
	}
}

func TestPublishingDestinationPaginationOwnershipAndEmptyUpdates(t *testing.T) {
	h := newDestinationControlFixture(t)
	id := h.create(t)
	out, err := filterCall(h.s, h.ctx, "ListPublishingDestinations", &api.ListPublishingDestinationsRequest{DetectorId: new(api.DetectorId(h.d.ID)), MaxResults: new(api.MaxResults(1))})
	if err != nil {
		t.Fatal(err)
	}
	first := out.(*api.ListPublishingDestinationsResponse)
	if len(first.Destinations) != 1 || value(first.Destinations[0].DestinationId) != id || value(first.Destinations[0].Status) != "PUBLISHING" || value(first.Destinations[0].DestinationType) != "S3" || value(first.NextToken) != id+"/S3" {
		t.Fatalf("unexpected native full page: %+v", first)
	}
	out, err = filterCall(h.s, h.ctx, "ListPublishingDestinations", &api.ListPublishingDestinationsRequest{DetectorId: new(api.DetectorId(h.d.ID)), MaxResults: new(api.MaxResults(1)), NextToken: first.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	last := out.(*api.ListPublishingDestinationsResponse)
	if last.Destinations == nil || len(last.Destinations) != 0 || last.NextToken != nil {
		t.Fatalf("last page was not an empty terminal page: %+v", last)
	}
	for _, limit := range []api.MaxResults{0, 51} {
		if _, err := filterCall(h.s, h.ctx, "ListPublishingDestinations", &api.ListPublishingDestinationsRequest{DetectorId: new(api.DetectorId(h.d.ID)), MaxResults: &limit}); err == nil || err.StatusCode != 400 {
			t.Fatalf("out-of-bounds limit %d accepted: %v", limit, err)
		}
	}
	for _, properties := range []*api.DestinationProperties{nil, {}} {
		if err := h.update(id, properties); err == nil || err.StatusCode != 400 {
			t.Fatalf("empty update accepted: %v", err)
		}
	}
	other := h.d
	other.ID = "fedcba9876543210fedcba9876543210"
	other.ARN = detectorARN(other.Scope, other.ID)
	if err := h.s.repository.Update(h.ctx, func(tx Transaction) error { return tx.PutDetector(other) }); err != nil {
		t.Fatal(err)
	}
	for _, detector := range []string{h.d.ID, other.ID} {
		token := "malformed"
		if detector == other.ID {
			token = value(first.NextToken)
		}
		if _, err := filterCall(h.s, h.ctx, "ListPublishingDestinations", &api.ListPublishingDestinationsRequest{DetectorId: new(api.DetectorId(detector)), NextToken: new(api.String(token))}); err == nil || err.StatusCode != 400 {
			t.Fatalf("invalid or cross-detector cursor accepted: %v", err)
		}
	}
	foreign := awsctx.WithMetadata(h.ctx, awsctx.Metadata{Partition: h.d.Partition, AccountID: "999999999999", Region: h.d.Region})
	if _, err := filterCall(h.s, foreign, "DescribePublishingDestination", &api.DescribePublishingDestinationRequest{DetectorId: new(api.DetectorId(h.d.ID)), DestinationId: new(api.String(id))}); err == nil || err.StatusCode != 400 {
		t.Fatalf("foreign account described destination: %v", err)
	}
}

func TestPublishingDestinationCreateRechecksQuotaAndAuthority(t *testing.T) {
	for _, change := range []string{"quota", "authority"} {
		t.Run(change, func(t *testing.T) {
			h := newDestinationControlFixture(t)
			winnerID := ""
			h.sink.validate = func(context.Context, PublishingDestination) error {
				h.sink.validate = nil
				if change == "authority" {
					h.auth.check = func(r authorization.Request) *awswire.Error {
						if r.Action == "guardduty:CreatePublishingDestination" {
							return failure("AccessDeniedException", "permission revoked", 403)
						}
						return nil
					}
					return nil
				}
				in := h.input()
				in.ClientToken = new(api.ClientToken("winner-token"))
				in.DestinationProperties.DestinationArn = new(api.String("arn:aws:s3:::winner"))
				out, err := filterCall(h.s, h.ctx, "CreatePublishingDestination", in)
				if err != nil {
					return err
				}
				winnerID = value(out.(*api.CreatePublishingDestinationResponse).DestinationId)
				return nil
			}
			_, rejected := filterCall(h.s, h.ctx, "CreatePublishingDestination", h.input())
			if change == "authority" {
				if rejected == nil || rejected.StatusCode != 403 {
					t.Fatalf("commit ignored revoked create authority: %v", rejected)
				}
				h.requireAbsent(t)
				return
			}
			if rejected == nil || rejected.StatusCode != 400 {
				t.Fatalf("commit exceeded current quota: %v", rejected)
			}
			if err := h.s.repository.View(h.ctx, func(r Reader) error {
				all, err := r.PublishingDestinations(h.d.Scope, h.d.ID)
				if len(all) != 1 || all[0].ID != winnerID || all[0].DestinationARN != "arn:aws:s3:::winner" {
					t.Fatalf("quota race changed winner: %+v", all)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPublishingDestinationReplayCannotResurrectDeletedResource(t *testing.T) {
	h := newDestinationControlFixture(t)
	id := h.create(t)
	h.sink.validate = func(context.Context, PublishingDestination) error {
		if err := h.remove(id); err != nil {
			return err
		}
		return nil
	}
	if _, err := filterCall(h.s, h.ctx, "CreatePublishingDestination", h.input()); err == nil {
		t.Fatal("replay resurrected a resource deleted during validation")
	}
	h.requireAbsent(t)
}
