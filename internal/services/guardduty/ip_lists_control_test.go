package guardduty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"stackd/storage/memory"
)

// This adapter isolates the lifecycle's transaction and external-read boundary.
// Real S3, IAM role assumption and KMS authorization belong to integration tests.
type controlListSource struct {
	policies  *memory.Store[map[string]string]
	putErr    error
	deleteErr error
	read      func(context.Context, IPList) ([]byte, error)
	reads     atomic.Int64
}

func (f *controlListSource) PutPolicy(ctx context.Context, v IPList) error {
	return f.policies.Update(ctx, func(p *map[string]string, _ *memory.Transaction) error {
		(*p)[v.ARN] = v.Location
		return f.putErr
	})
}
func (f *controlListSource) DeletePolicy(ctx context.Context, v IPList) error {
	return f.policies.Update(ctx, func(p *map[string]string, _ *memory.Transaction) error {
		delete(*p, v.ARN)
		return f.deleteErr
	})
}
func (f *controlListSource) Read(ctx context.Context, v IPList) ([]byte, error) {
	f.reads.Add(1)
	if f.read != nil {
		return f.read(ctx, v)
	}
	return []byte("198.51.100.10\n"), nil
}

type controlFixture struct {
	s      *Service
	ctx    context.Context
	d      Detector
	source *controlListSource
	auth   *filterTestAuthorizer
	events journal.Storage
}

func newControlFixture(t *testing.T) controlFixture {
	t.Helper()
	domain := memory.NewDomain()
	source := &controlListSource{policies: memory.New(domain, map[string]string{}, maps.Clone[map[string]string])}
	events := journal.NewMemory(domain)
	auth := &filterTestAuthorizer{}
	s := New(Config{Repository: NewMemoryRepository(domain), IPLists: source, Authorizer: auth, Recorder: apievents.New(events), Clock: clock.NewManual(time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC))})
	t.Cleanup(func() { _ = s.Close() })
	d := Detector{Scope: Scope{"aws", "123456789012", "us-east-1"}, ID: "0123456789abcdef0123456789abcdef", Status: "ENABLED"}
	d.ARN = detectorARN(d.Scope, d.ID)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: d.Partition, AccountID: d.AccountID, Region: d.Region, PrincipalARN: "arn:aws:iam::123456789012:user/list-owner", AccessKeyID: "caller-key", RequestID: "caller-request", SourceIP: "192.0.2.9", UserAgent: "list-client"})
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDetector(d) }); err != nil {
		t.Fatal(err)
	}
	return controlFixture{s, ctx, d, source, auth, events}
}
func (h controlFixture) create(t *testing.T, kind IPListKind, name, token string, active bool) (string, *awswire.Error) {
	t.Helper()
	var out any
	var err *awswire.Error
	if kind == TrustedIPList {
		out, err = filterCall(h.s, h.ctx, "CreateIPSet", &api.CreateIPSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), Name: new(api.Name(name)), ClientToken: new(api.ClientToken(token)), Format: new(api.IpSetFormat("TXT")), Location: new(api.Location("s3://owned/source.txt")), Activate: new(api.Boolean(active)), Tags: api.TagMap{"team": "blue"}})
		if err == nil {
			return value(out.(*api.CreateIPSetResponse).IpSetId), nil
		}
	} else {
		out, err = filterCall(h.s, h.ctx, "CreateThreatIntelSet", &api.CreateThreatIntelSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), Name: new(api.Name(name)), ClientToken: new(api.ClientToken(token)), Format: new(api.ThreatIntelSetFormat("TXT")), Location: new(api.Location("s3://owned/source.txt")), Activate: new(api.Boolean(active)), Tags: api.TagMap{"team": "blue"}})
		if err == nil {
			return value(out.(*api.CreateThreatIntelSetResponse).ThreatIntelSetId), nil
		}
	}
	return "", err
}
func (h controlFixture) update(kind IPListKind, id string, active *api.Boolean, location *api.Location) *awswire.Error {
	if kind == TrustedIPList {
		_, err := filterCall(h.s, h.ctx, "UpdateIPSet", &api.UpdateIPSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), IpSetId: new(api.String(id)), Activate: active, Location: location})
		return err
	}
	_, err := filterCall(h.s, h.ctx, "UpdateThreatIntelSet", &api.UpdateThreatIntelSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), ThreatIntelSetId: new(api.String(id)), Activate: active, Location: location})
	return err
}
func (h controlFixture) remove(kind IPListKind, id string) *awswire.Error {
	if kind == TrustedIPList {
		_, err := filterCall(h.s, h.ctx, "DeleteIPSet", &api.DeleteIPSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), IpSetId: new(api.String(id))})
		return err
	}
	_, err := filterCall(h.s, h.ctx, "DeleteThreatIntelSet", &api.DeleteThreatIntelSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), ThreatIntelSetId: new(api.String(id))})
	return err
}
func (h controlFixture) list(t *testing.T, kind IPListKind, id string) IPList {
	t.Helper()
	var v IPList
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		var err error
		v, err = r.IPList(h.d.Scope, h.d.ID, kind, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return v
}
func (h controlFixture) matches(t *testing.T, ip string) []IPList {
	t.Helper()
	address, err := ipListAddress(ip)
	if err != nil {
		t.Fatal(err)
	}
	var matches []IPList
	if err := h.s.repository.View(h.ctx, func(r Reader) error {
		var err error
		matches, err = r.MatchingIPLists(h.d.Scope, h.d.ID, address)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return matches
}

func TestIPListSourceFailureCommitsErrorAndActualOutcome(t *testing.T) {
	for _, kind := range []IPListKind{TrustedIPList, ThreatIPList} {
		t.Run(string(kind), func(t *testing.T) {
			h := newControlFixture(t)
			id, err := h.create(t, kind, "owned", "token", false)
			if err != nil {
				t.Fatal(err)
			}
			if h.source.reads.Load() != 0 || h.list(t, kind, id).Status != "INACTIVE" {
				t.Fatal("inactive create read its source")
			}
			h.source.read = func(ctx context.Context, pending IPList) ([]byte, error) {
				// A separate context can acquire storage only after admission commits.
				probe, cancel := context.WithTimeout(h.ctx, time.Second)
				defer cancel()
				if err := h.s.repository.View(probe, func(r Reader) error {
					v, err := r.IPList(pending.Scope, pending.DetectorID, pending.Kind, pending.ID)
					if err != nil {
						return err
					}
					if v.Status != "ACTIVATING" || v.Version != pending.Version || v.Due.IsZero() {
						return errors.New("source intent was not committed")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if ctx.Err() != nil || apievents.EventID(ctx) == "" {
					t.Fatal("read received expired or unreserved context")
				}
				return nil, failure("InternalServerErrorException", "source denied", 400)
			}
			err = h.update(kind, id, new(api.Boolean(true)), new(api.Location("s3://owned/missing.txt")))
			if err == nil || err.Code != "InternalServerErrorException" || err.StatusCode != 400 {
				t.Fatalf("source error: %v", err)
			}
			v := h.list(t, kind, id)
			if v.Status != "ERROR" || v.Location != "s3://owned/missing.txt" || !v.Due.IsZero() {
				t.Fatalf("failed ingestion lost intent: %+v", v)
			}
			rows, readErr := h.events.Read(h.ctx, 0, 100)
			if readErr != nil {
				t.Fatal(readErr)
			}
			last := rows[len(rows)-1]
			if last.APICallCompleted.ErrorCode != err.Code || last.ActorARN != awsctx.FromContext(h.ctx).PrincipalARN || last.RequestID != "caller-request" || last.APICallCompleted.SourceIPAddress != "192.0.2.9" || last.APICallCompleted.UserAgent != "list-client" {
				t.Fatalf("incorrect final API outcome or caller attribution: %+v", last)
			}
			h.source.read = func(context.Context, IPList) ([]byte, error) { return []byte("not-an-ip"), nil }
			if err = h.update(kind, id, new(api.Boolean(true)), nil); err == nil || err.Code != "BadRequestException" || h.list(t, kind, id).Status != "ERROR" {
				t.Fatalf("parser failure not retained: %v", err)
			}
			h.source.read = nil
			if err = h.update(kind, id, new(api.Boolean(true)), new(api.Location("s3://owned/corrected.txt"))); err != nil {
				t.Fatal(err)
			}
			if h.list(t, kind, id).Status != "ACTIVE" || len(h.matches(t, "198.51.100.10")) != 1 {
				t.Fatal("corrected source did not become effective")
			}
		})
	}
}

func TestIPListIAMAdmissionRollsBackListAndPolicy(t *testing.T) {
	for _, kind := range []IPListKind{TrustedIPList, ThreatIPList} {
		t.Run(string(kind), func(t *testing.T) {
			h := newControlFixture(t)
			h.source.putErr = failure("AccessDeniedException", "iam:PutRolePolicy denied", 403)
			if _, err := h.create(t, kind, "owned", "token", true); err == nil || err.StatusCode != 403 {
				t.Fatalf("admission error: %v", err)
			}
			if err := h.s.repository.View(h.ctx, func(r Reader) error {
				lists, err := r.IPLists(h.d.Scope, h.d.ID)
				if len(lists) != 0 {
					t.Fatal("denied create left a list")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := h.source.policies.View(h.ctx, func(p *map[string]string, _ *memory.Transaction) error {
				if len(*p) != 0 {
					t.Fatal("denied admission committed policy")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if h.source.reads.Load() != 0 {
				t.Fatal("denied admission read S3")
			}
			h.source.putErr = nil
			id, err := h.create(t, kind, "owned", "token", true)
			if err != nil {
				t.Fatal(err)
			}
			before := h.list(t, kind, id)
			h.source.putErr = failure("AccessDeniedException", "iam:PutRolePolicy denied", 403)
			if err := h.update(kind, id, new(api.Boolean(true)), new(api.Location("s3://owned/denied.txt"))); err == nil {
				t.Fatal("denied update succeeded")
			}
			if got := h.list(t, kind, id); !reflect.DeepEqual(got, before) {
				t.Fatalf("denied update changed list: %+v", got)
			}
			h.source.deleteErr = failure("AccessDeniedException", "iam:DeleteRolePolicy denied", 403)
			if err := h.remove(kind, id); err == nil {
				t.Fatal("denied deletion succeeded")
			}
			if got := h.list(t, kind, id); !reflect.DeepEqual(got, before) || len(h.matches(t, "198.51.100.10")) != 1 {
				t.Fatal("denied deletion lost effective ranges")
			}
		})
	}
}

func TestIPListReadsOnlyOnRequestedActivation(t *testing.T) {
	h := newControlFixture(t)
	id, err := h.create(t, TrustedIPList, "owned", "token", true)
	if err != nil {
		t.Fatal(err)
	}
	h.source.read = func(context.Context, IPList) ([]byte, error) { return []byte("203.0.113.7\n"), nil }
	if _, err := filterCall(h.s, h.ctx, "GetIPSet", &api.GetIPSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), IpSetId: new(api.String(id))}); err != nil {
		t.Fatal(err)
	}
	if err := h.update(TrustedIPList, id, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.jobs.RunDue(h.ctx, 10); err != nil {
		t.Fatal(err)
	}
	if h.source.reads.Load() != 1 || len(h.matches(t, "198.51.100.10")) != 1 || len(h.matches(t, "203.0.113.7")) != 0 {
		t.Fatal("source changed without reactivation")
	}
	if err := h.update(TrustedIPList, id, new(api.Boolean(true)), nil); err != nil {
		t.Fatal(err)
	}
	if h.source.reads.Load() != 2 || len(h.matches(t, "198.51.100.10")) != 0 || len(h.matches(t, "203.0.113.7")) != 1 {
		t.Fatal("reactivation did not replace ranges")
	}
	if err := h.update(TrustedIPList, id, new(api.Boolean(false)), nil); err != nil {
		t.Fatal(err)
	}
	if h.source.reads.Load() != 2 || len(h.matches(t, "203.0.113.7")) != 0 || h.list(t, TrustedIPList, id).Status != "INACTIVE" {
		t.Fatal("deactivation retained effective ranges or read source")
	}
}

func TestIPListStaleCompletionAndRecovery(t *testing.T) {
	h := newControlFixture(t)
	id, err := h.create(t, TrustedIPList, "owned", "token", false)
	if err != nil {
		t.Fatal(err)
	}
	var stale scheduler.Job
	h.source.read = func(ctx context.Context, pending IPList) ([]byte, error) {
		stale = scheduler.Job{Key: pending.ARN, Due: pending.Due, Version: uint64(pending.Version)}
		h.source.read = nil
		if err := h.update(TrustedIPList, id, new(api.Boolean(true)), new(api.Location("s3://owned/corrected.txt"))); err != nil {
			t.Fatal(err)
		}
		return []byte("203.0.113.99\n"), nil
	}
	if err := h.update(TrustedIPList, id, new(api.Boolean(true)), nil); err != nil {
		t.Fatal(err)
	}
	v := h.list(t, TrustedIPList, id)
	if v.Status != "ACTIVE" || v.Location != "s3://owned/corrected.txt" || len(h.matches(t, "198.51.100.10")) != 1 || len(h.matches(t, "203.0.113.99")) != 0 {
		t.Fatal("stale completion overwrote newer source")
	}
	if err := (ipListJobs{h.s}).Run(h.ctx, stale); err != nil {
		t.Fatal(err)
	}
	if h.source.reads.Load() != 2 {
		t.Fatal("stale recovery job read source")
	}
	h.s.jobs.Close()
	v.Status, v.Due = "ACTIVATING", h.s.clock.Now().Add(-time.Second)
	v.Version++
	if err := h.s.repository.Update(h.ctx, func(tx Transaction) error { return tx.PutIPList(v) }); err != nil {
		t.Fatal(err)
	}
	job, found, jobErr := (ipListJobs{h.s}).Next(h.ctx)
	if jobErr != nil || !found || job.Version != uint64(v.Version) {
		t.Fatalf("pending activation not recoverable: %+v %v", job, jobErr)
	}
	if err := (ipListJobs{h.s}).Run(h.ctx, job); err != nil {
		t.Fatal(err)
	}
	if h.source.reads.Load() != 3 || h.list(t, TrustedIPList, id).Status != "ACTIVE" {
		t.Fatal("recovery failed to ingest")
	}
	if _, found, err := (ipListJobs{h.s}).Next(h.ctx); err != nil || found {
		t.Fatalf("completed activation rescheduled: found=%v err=%v", found, err)
	}
}

func TestIPListTombstonesQuotaReplayAndScopedPagination(t *testing.T) {
	for _, kind := range []IPListKind{TrustedIPList, ThreatIPList} {
		t.Run(string(kind), func(t *testing.T) {
			h := newControlFixture(t)
			id, err := h.create(t, kind, "owned", "token", true)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := h.create(t, kind, "owned", "token", false)
			if err != nil || replay != id || h.source.reads.Load() != 1 {
				t.Fatalf("replay reingested or replaced list: %s %v", replay, err)
			}
			changedTags := api.TagMap{"team": "red", "ignored": "yes"}
			var replayInput any
			operation := "CreateIPSet"
			if kind == TrustedIPList {
				replayInput = &api.CreateIPSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), Name: new(api.Name("owned")), ClientToken: new(api.ClientToken("token")), Format: new(api.IpSetFormat("TXT")), Location: new(api.Location("s3://owned/source.txt")), Activate: new(api.Boolean(false)), Tags: changedTags}
			} else {
				operation = "CreateThreatIntelSet"
				replayInput = &api.CreateThreatIntelSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), Name: new(api.Name("owned")), ClientToken: new(api.ClientToken("token")), Format: new(api.ThreatIntelSetFormat("TXT")), Location: new(api.Location("s3://owned/source.txt")), Activate: new(api.Boolean(false)), Tags: changedTags}
			}
			if _, err := filterCall(h.s, h.ctx, operation, replayInput); err != nil {
				t.Fatal(err)
			}
			if got := h.list(t, kind, id); !reflect.DeepEqual(got.Tags, map[string]string{"team": "blue"}) || got.Status != "ACTIVE" {
				t.Fatalf("token replay applied changed tags or activation: %+v", got)
			}
			if _, err := h.create(t, kind, "owned", "different-token", false); err == nil {
				t.Fatal("duplicate name with different token succeeded")
			}
			quota := 1
			if kind == ThreatIPList {
				quota = 6
			}
			for i := 1; i < quota; i++ {
				if _, err := h.create(t, kind, fmt.Sprintf("list-%d", i), "token", false); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.create(t, kind, "overflow", "token", false); err == nil || err.Code != "InternalServerErrorException" || err.StatusCode != 400 {
				t.Fatalf("quota error: %v", err)
			}
			if err := h.remove(kind, id); err != nil {
				t.Fatal(err)
			}
			v := h.list(t, kind, id)
			if v.Status != "DELETED" || len(v.Tags) != 0 || len(h.matches(t, "198.51.100.10")) != 0 {
				t.Fatalf("incorrect tombstone: %+v", v)
			}
			if err := h.remove(kind, id); err == nil || err.Code != "BadRequestException" {
				t.Fatalf("repeat delete error: %v", err)
			}
			fresh, err := h.create(t, kind, "owned", "token", false)
			if err != nil || fresh == id {
				t.Fatalf("tombstone consumed quota or replay identity: %s %v", fresh, err)
			}
			if kind == TrustedIPList {
				return
			}
			out, rejected := filterCall(h.s, h.ctx, "ListThreatIntelSets", &api.ListThreatIntelSetsRequest{DetectorId: new(api.DetectorId(h.d.ID)), MaxResults: new(api.MaxResults(1))})
			if rejected != nil {
				t.Fatal(rejected)
			}
			first := out.(*api.ListThreatIntelSetsResponse)
			if len(first.ThreatIntelSetIds) != 1 || value(first.NextToken) == "" {
				t.Fatalf("bad first page: %+v", first)
			}
			other := h.d
			other.ID = newID()
			if err := h.s.repository.Update(h.ctx, func(tx Transaction) error { return tx.PutDetector(other) }); err != nil {
				t.Fatal(err)
			}
			if _, rejected := filterCall(h.s, h.ctx, "ListThreatIntelSets", &api.ListThreatIntelSetsRequest{DetectorId: new(api.DetectorId(other.ID)), NextToken: first.NextToken}); rejected == nil {
				t.Fatal("cross-detector cursor accepted")
			}
			seen := map[string]bool{value(&first.ThreatIntelSetIds[0]): true}
			next := first.NextToken
			for next != nil {
				out, rejected = filterCall(h.s, h.ctx, "ListThreatIntelSets", &api.ListThreatIntelSetsRequest{DetectorId: new(api.DetectorId(h.d.ID)), MaxResults: new(api.MaxResults(1)), NextToken: next})
				if rejected != nil {
					t.Fatal(rejected)
				}
				p := out.(*api.ListThreatIntelSetsResponse)
				for _, item := range p.ThreatIntelSetIds {
					if seen[string(item)] || string(item) == id {
						t.Fatal("duplicate or deleted ID in pagination")
					}
					seen[string(item)] = true
				}
				next = p.NextToken
			}
			if len(seen) != quota || !seen[fresh] {
				t.Fatalf("incomplete pages: %v", seen)
			}
		})
	}
}

func TestIPListCurrentAuthorizationAndTags(t *testing.T) {
	h := newControlFixture(t)
	h.auth.check = func(r authorization.Request) *awswire.Error {
		if (r.Action == "guardduty:CreateIPSet" || r.Action == "guardduty:ListIPSets") && r.ResourceARN != "*" {
			return failure("AccessDeniedException", "not a wildcard action", 403)
		}
		return nil
	}
	id, err := h.create(t, TrustedIPList, "owned", "token", false)
	if err != nil {
		t.Fatal(err)
	}
	arn := ipListARN(h.d.Scope, h.d.ID, TrustedIPList, id)
	if _, err := filterCall(h.s, h.ctx, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.GuardDutyArn(arn)), Tags: api.TagMap{"team": "green", "added": "yes"}}); err != nil {
		t.Fatal(err)
	}
	h.auth.check = func(r authorization.Request) *awswire.Error {
		if r.Action == "guardduty:ListIPSets" && r.ResourceARN == "*" {
			return nil
		}
		if r.ResourceARN != arn || len(r.Context["aws:ResourceTag/team"]) != 1 || r.Context["aws:ResourceTag/team"][0] != "green" {
			return failure("AccessDeniedException", "current child tags required", 403)
		}
		return nil
	}
	if _, err := filterCall(h.s, h.ctx, "GetIPSet", &api.GetIPSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), IpSetId: new(api.String(id))}); err != nil {
		t.Fatal(err)
	}
	if _, err := filterCall(h.s, h.ctx, "ListIPSets", &api.ListIPSetsRequest{DetectorId: new(api.DetectorId(h.d.ID))}); err != nil {
		t.Fatal(err)
	}
	if _, err := filterCall(h.s, h.ctx, "UntagResource", &api.UntagResourceRequest{ResourceArn: new(api.GuardDutyArn(arn)), TagKeys: api.TagKeyList{"added"}}); err != nil {
		t.Fatal(err)
	}
	out, rejected := filterCall(h.s, h.ctx, "ListTagsForResource", &api.ListTagsForResourceRequest{ResourceArn: new(api.GuardDutyArn(arn))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if !reflect.DeepEqual(out.(*api.ListTagsForResourceResponse).Tags, api.TagMap{"team": "green"}) {
		t.Fatalf("tag merge/removal: %+v", out)
	}
	h.auth.check = func(authorization.Request) *awswire.Error { return failure("AccessDeniedException", "revoked", 403) }
	if err := h.update(TrustedIPList, id, new(api.Boolean(true)), nil); err == nil || h.source.reads.Load() != 0 {
		t.Fatal("revoked permission ingested a source")
	}
}

func TestIPListCapturedValidationAndLongUpdateName(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/guardduty/ip_lists.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case   string `json:"case"`
			Code   string `json:"code"`
			Status int    `json:"http_status"`
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		code   string
		status int
	}
	outcomes := map[string]outcome{}
	for _, row := range capture.Observations {
		outcomes[row.Case] = outcome{row.Code, row.Status}
	}
	h := newControlFixture(t)
	id, rejected := h.create(t, TrustedIPList, "owned", "token", false)
	if rejected != nil {
		t.Fatal(rejected)
	}
	for _, tc := range []struct {
		name    string
		request *api.UpdateIPSetRequest
	}{
		{"ip-update-empty-name", &api.UpdateIPSetRequest{Name: new(api.Name(""))}},
		{"ip-update-punctuation-name", &api.UpdateIPSetRequest{Name: new(api.Name("owned!list.name"))}},
		{"ip-update-invalid-owner-length", &api.UpdateIPSetRequest{ExpectedBucketOwner: new(api.AccountId("123"))}},
	} {
		tc.request.DetectorId, tc.request.IpSetId = new(api.DetectorId(h.d.ID)), new(api.String(id))
		_, rejected := filterCall(h.s, h.ctx, "UpdateIPSet", tc.request)
		want, ok := outcomes[tc.name]
		if !ok || rejected == nil || rejected.Code != want.code || rejected.StatusCode != want.status {
			t.Fatalf("%s: native=%+v local=%v", tc.name, want, rejected)
		}
	}
	name := strings.Repeat("x", 301)
	if _, rejected := filterCall(h.s, h.ctx, "UpdateIPSet", &api.UpdateIPSetRequest{DetectorId: new(api.DetectorId(h.d.ID)), IpSetId: new(api.String(id)), Name: new(api.Name(name))}); rejected != nil {
		t.Fatal(rejected)
	}
	if outcomes["ip-update-long-name"].code != "Success" || h.list(t, TrustedIPList, id).Name != name {
		t.Fatal("captured 301-character update name was truncated or rejected")
	}
}
