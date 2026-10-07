package integrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	trailapi "stackd/internal/awsapi/cloudtrail"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/iam"
	"stackd/internal/services/s3"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	trailstore "stackd/storage/sqlite/cloudtrail"
)

// This boundary always performs the real S3 preflight first. The one-shot hook
// deterministically interleaves native commands while no trail transaction is held.
type cfnTrailCheckedDestination struct {
	CloudTrailS3
	after func()
}

func (d *cfnTrailCheckedDestination) Validate(ctx context.Context, trail cloudtrail.TrailRecord, parent string) (string, *awswire.Error) {
	key, wire := d.CloudTrailS3.Validate(ctx, trail, parent)
	if wire == nil && d.after != nil {
		after := d.after
		d.after = nil
		after()
	}
	return key, wire
}

type cfnPrivateTrailFixture struct {
	ctx         context.Context
	path        string
	db          *sql.DB
	repository  cloudtrail.Repository
	config      cloudtrail.Config
	owner       *cloudtrail.Service
	buckets     *s3.Service
	identities  *iam.Service
	destination *cfnTrailCheckedDestination
	commands    StepFunctionsCommands
	h           cfnTrail
}

func newCFNPrivateTrailFixture(t *testing.T, backend string) *cfnPrivateTrailFixture {
	t.Helper()
	f := &cfnPrivateTrailFixture{ctx: cfnWorkflowOwnerContext(t)}
	source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
	domain := memory.NewDomain()
	identities := iam.NewMemoryRepository(domain)
	credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(identities, nil), Clock: source})
	f.identities = iam.NewWithConfig(iam.Config{Repository: identities, Credentials: credentials, Clock: source})
	authorizer := authorization.NewWithClock(f.identities, nil, source)
	f.buckets = s3.New(s3.Config{Repository: s3.NewMemoryRepository(domain), Authorizer: authorizer, Clock: source})
	f.repository = cloudtrail.NewMemoryRepository(domain)
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "trails.sqlite")
		f.open(t)
	}
	f.destination = &cfnTrailCheckedDestination{CloudTrailS3: CloudTrailS3{S3: f.buckets}}
	f.config = cloudtrail.Config{Repository: f.repository, Destination: f.destination, Authorizer: authorizer, Clock: source}
	f.start()
	t.Cleanup(func() {
		_ = f.owner.Close()
		_ = f.buckets.Close()
		_ = f.identities.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	f.native(t, "s3", "CreateBucket", map[string]any{"Bucket": "private-trail-logs"})
	f.native(t, "s3", "PutBucketPolicy", map[string]any{"Bucket": "private-trail-logs", "Policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::private-trail-logs"},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::private-trail-logs/*","Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}}]}`})
	return f
}

func (f *cfnPrivateTrailFixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.db, err = sqlite.Open(f.ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.repository = trailstore.New(f.db)
}

func (f *cfnPrivateTrailFixture) start() {
	f.config.Repository = f.repository
	f.owner = cloudtrail.New(f.config)
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"cloudtrail": f.owner, "s3": f.buckets, "iam": f.identities})
	f.h = cfnTrail{f.commands}
}

func (f *cfnPrivateTrailFixture) reopen(t *testing.T) {
	t.Helper()
	if f.path == "" {
		return
	}
	if err := f.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	f.start()
}

func (f *cfnPrivateTrailFixture) native(t *testing.T, service, operation string, input map[string]any) {
	t.Helper()
	if err := cfnComputeRun(f.ctx, f.commands, service, operation, input); err != nil {
		t.Fatalf("%s.%s: %v", service, operation, err)
	}
}

func cfnPrivateTrailRequest() cloudformation.ResourceRequest {
	return cfnWorkflowOwnerRequest("AWS::CloudTrail::Trail", "Trail", cloudformation.Properties{
		"TrailName": "private-trail", "S3BucketName": "private-trail-logs", "IsLogging": false,
		"Tags": []any{map[string]any{"Key": "team", "Value": "original"}},
	})
}

func (f *cfnPrivateTrailFixture) row(t *testing.T) cloudtrail.TrailRecord {
	t.Helper()
	var row cloudtrail.TrailRecord
	if err := f.repository.View(f.ctx, func(r cloudtrail.Reader) error {
		var err error
		row, err = r.Trail(cloudtrail.TrailKey{Scope: cloudtrail.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "private-trail"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return row
}

func cfnPrivateTrailReject(t *testing.T, result cloudformation.ResourceResult, err error) {
	t.Helper()
	if err == nil || cfnTrailMissing(err) || result.PhysicalID != "" {
		t.Fatalf("foreign incarnation adopted or certified absent: %+v %v", result, err)
	}
}

func TestCFNTrailPublicTagsCannotAdoptNativeTrail(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, cc := range []bool{false, true} {
			name := "CFN"
			if cc {
				name = "CC"
			}
			t.Run(backend+"/"+name, func(t *testing.T) {
				f := newCFNPrivateTrailFixture(t, backend)
				r := cfnPrivateTrailRequest()
				r.CloudControl = cc
				counterfeit := cfnComputeOwnedTags(r)
				counterfeit["stackd:cloudformation:owner"] = cfnLogsMarker(r)
				f.native(t, "cloudtrail", "CreateTrail", map[string]any{"Name": "private-trail", "S3BucketName": "private-trail-logs"})
				f.native(t, "cloudtrail", "AddTags", map[string]any{"ResourceId": "private-trail", "TagsList": cfnComputeTagList(counterfeit)})
				f.reopen(t)
				before := f.row(t)
				if before.CFNOwner != "" {
					t.Fatal("native public tags created a private owner")
				}
				out, err := f.h.Create(f.ctx, r)
				cfnPrivateTrailReject(t, out, err)
				out, err = f.h.RecoverCreation(f.ctx, r)
				cfnPrivateTrailReject(t, out, err)
				r.PhysicalID = "private-trail"
				r.CloudControl = false
				if _, err := f.h.Update(f.ctx, r); err == nil {
					t.Fatal("counterfeit tags authorized CFN update")
				}
				if err := f.h.Delete(f.ctx, r); err == nil {
					t.Fatal("counterfeit tags authorized CFN delete")
				}
				if after := f.row(t); !reflect.DeepEqual(before, after) {
					t.Fatal("rejected ownership changed the real native trail")
				}
				if _, err := f.h.Read(f.ctx, r); err != nil {
					t.Fatalf("native-readable foreign trail was hidden: %v", err)
				}
				r.CloudControl = true
				if _, err := f.h.Update(f.ctx, r); err != nil {
					t.Fatalf("CC update incorrectly required a private owner: %v", err)
				}
				if f.row(t).CFNOwner != "" {
					t.Fatal("CC update adopted a native trail")
				}
				if err := f.h.Delete(f.ctx, r); err != nil {
					t.Fatalf("CC delete incorrectly required a private owner: %v", err)
				}
			})
		}
	}
}

func TestCFNTrailPrivateOwnerSurvivesTagForgeryAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNPrivateTrailFixture(t, backend)
			r := cfnPrivateTrailRequest()
			created, err := f.h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			before := f.row(t)
			if before.CFNOwner != cfnLogsMarker(r) {
				t.Fatal("CFN create did not persist its private owner on the actual trail")
			}
			tags, err := f.h.tags(f.ctx, created.Attributes["Arn"].(string))
			if err != nil {
				t.Fatal(err)
			}
			for key := range tags {
				if strings.HasPrefix(key, cfnComputeTagPrefix) {
					t.Fatalf("create exposed a private claim through tags: %s", key)
				}
			}
			foreign := r
			foreign.Token = "foreign-incarnation"
			counterfeit := cfnComputeOwnedTags(foreign)
			counterfeit["stackd:cloudformation:owner"] = cfnLogsMarker(foreign)
			f.native(t, "cloudtrail", "AddTags", map[string]any{"ResourceId": "private-trail", "TagsList": cfnComputeTagList(counterfeit)})
			f.native(t, "cloudtrail", "RemoveTags", map[string]any{"ResourceId": "private-trail", "TagsList": []any{map[string]any{"Key": "stackd:cloudformation:incarnation"}}})
			f.reopen(t)
			recovered, err := f.h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("tag mutation revoked authentic recovery: %+v %v", recovered, err)
			}
			out, err := f.h.Create(f.ctx, foreign)
			cfnPrivateTrailReject(t, out, err)
			out, err = f.h.RecoverCreation(f.ctx, foreign)
			cfnPrivateTrailReject(t, out, err)
			if err := f.h.Delete(f.ctx, foreign); err == nil {
				t.Fatal("forged tags deleted the privately owned trail")
			}
			if f.row(t).CFNOwner != before.CFNOwner {
				t.Fatal("native tag mutation rewrote the private owner")
			}
			f.native(t, "cloudtrail", "DeleteTrail", map[string]any{"Name": "private-trail"})
			counterfeit = cfnComputeOwnedTags(r)
			counterfeit["stackd:cloudformation:owner"] = cfnLogsMarker(r)
			f.native(t, "cloudtrail", "CreateTrail", map[string]any{"Name": "private-trail", "S3BucketName": "private-trail-logs", "TagsList": cfnComputeTagList(counterfeit)})
			f.reopen(t)
			if f.row(t).ID == before.ID || f.row(t).CFNOwner != "" {
				t.Fatal("native recreation retained the old incarnation")
			}
			out, err = f.h.RecoverCreation(f.ctx, r)
			cfnPrivateTrailReject(t, out, err)
			out, err = f.h.Create(f.ctx, r)
			cfnPrivateTrailReject(t, out, err)
			if _, err := f.h.Update(f.ctx, r); err == nil {
				t.Fatal("old owner updated a foreign recreation")
			}
			if err := f.h.Delete(f.ctx, r); err == nil {
				t.Fatal("old owner deleted a foreign recreation")
			}
			r.CloudControl = true
			if err := f.h.Delete(f.ctx, r); err != nil {
				t.Fatalf("current-IAM CC delete failed: %v", err)
			}
		})
	}
}

type cfnTrailLostReply struct {
	*cloudtrail.Service
	lose bool
}

func (e *cfnTrailLostReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, wire := e.Service.ExecuteCommand(ctx, r)
	if wire == nil && e.lose && string(r.Operation.Name) == "CreateTrail" {
		e.lose = false
		return nil, &awswire.Error{Code: "InvalidParameterException", Message: "lost admitted native create reply", StatusCode: 400}
	}
	return out, wire
}

func TestCFNTrailAdmittedFailuresRecoverExactCreationAfterReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, failure := range []string{"lost-reply", "selectors"} {
			t.Run(backend+"/"+failure, func(t *testing.T) {
				f := newCFNPrivateTrailFixture(t, backend)
				r := cfnPrivateTrailRequest()
				r.CloudControl = true
				if failure == "lost-reply" {
					f.h = cfnTrail{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"cloudtrail": &cfnTrailLostReply{Service: f.owner, lose: true}})}
				} else {
					r.Properties["EventSelectors"] = []any{map[string]any{"ReadWriteType": "Counterfeit"}}
				}
				created, err := f.h.Create(f.ctx, r)
				if err == nil || created.PhysicalID != "private-trail" {
					t.Fatalf("postadmission failure forgot authentic ID: %+v %v", created, err)
				}
				before := f.row(t)
				if before.CFNOwner != cfnLogsMarker(r) {
					t.Fatal("CC create did not claim privately")
				}
				f.reopen(t)
				f.h = cfnTrail{f.commands}
				recovered, err := f.h.RecoverCreation(f.ctx, r)
				if err != nil || recovered.PhysicalID != created.PhysicalID {
					t.Fatalf("exact private recovery failed: %+v %v", recovered, err)
				}
				replayed, err := f.h.Create(f.ctx, r)
				if failure == "selectors" {
					if err == nil || replayed.PhysicalID != created.PhysicalID {
						t.Fatalf("failed same-token convergence lost admitted ID: %+v %v", replayed, err)
					}
					delete(r.Properties, "EventSelectors")
					replayed, err = f.h.Create(f.ctx, r)
				}
				if err != nil || replayed.PhysicalID != created.PhysicalID || f.row(t).ID != before.ID {
					t.Fatalf("same-token replay changed the native incarnation: %+v %v", replayed, err)
				}
				r.PhysicalID = created.PhysicalID
				r.CloudControl = false
				if err := f.h.Delete(f.ctx, r); err != nil {
					t.Fatalf("exact rollback failed: %v", err)
				}
				if out, err := f.h.RecoverCreation(f.ctx, r); !cfnTrailMissing(err) || out.PhysicalID != "" {
					t.Fatalf("deleted exact creation was not absent: %+v %v", out, err)
				}
			})
		}
	}
}

func (f *cfnPrivateTrailFixture) user(t *testing.T) context.Context {
	t.Helper()
	out, err := cfnComputeCall[iamapi.CreateUserOutput](f.ctx, f.commands, "iam", "CreateUser", map[string]any{"UserName": "trail-owner"})
	if err != nil {
		t.Fatal(err)
	}
	f.native(t, "iam", "PutUserPolicy", map[string]any{"UserName": "trail-owner", "PolicyName": "trail", "PolicyDocument": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"cloudtrail:*","Resource":"*"}}`})
	metadata := awsctx.FromContext(f.ctx)
	metadata.PrincipalARN, metadata.PrincipalID = cfnComputeValue(out.User.Arn), cfnComputeValue(out.User.UserId)
	return awsctx.WithMetadata(f.ctx, metadata)
}

func TestCFNTrailNativeCommitRechecksCurrentIAMAndIncarnation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNPrivateTrailFixture(t, backend)
			user := f.user(t)
			r := cfnPrivateTrailRequest()
			created, err := f.h.Create(user, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			before := f.row(t)
			f.destination.after = func() {
				f.native(t, "iam", "DeleteUserPolicy", map[string]any{"UserName": "trail-owner", "PolicyName": "trail"})
			}
			r.Properties["S3KeyPrefix"] = "must-not-commit"
			if _, err := f.h.Update(user, r); err == nil {
				t.Fatal("destination preflight cached obsolete IAM permission")
			}
			if after := f.row(t); !reflect.DeepEqual(before, after) {
				t.Fatal("revoked IAM still committed trail configuration")
			}
			for _, cc := range []bool{false, true} {
				r.CloudControl = cc
				if _, err := f.h.Update(user, r); err == nil {
					t.Fatal("private owner bypassed current IAM update")
				}
				if err := f.h.Delete(user, r); err == nil {
					t.Fatal("private owner bypassed current IAM delete")
				}
				if _, err := f.h.Read(user, r); err == nil {
					t.Fatal("read bypassed current IAM")
				}
				if out, err := f.h.RecoverCreation(user, r); err == nil || cfnTrailMissing(err) || out.PhysicalID != "" {
					t.Fatalf("unauthorized recovery observed or certified absent: %+v %v", out, err)
				}
			}
			r.CloudControl = false
			f.destination.after = func() {
				f.native(t, "cloudtrail", "DeleteTrail", map[string]any{"Name": "private-trail"})
				f.native(t, "cloudtrail", "CreateTrail", map[string]any{"Name": "private-trail", "S3BucketName": "private-trail-logs", "TagsList": cfnComputeTagList(cfnComputeOwnedTags(r))})
			}
			if _, err := f.h.Update(f.ctx, r); err == nil {
				t.Fatal("destination preflight overwrote a foreign recreation")
			}
			after := f.row(t)
			if after.ID == before.ID || after.CFNOwner != "" || after.Prefix != "" {
				t.Fatal("postvalidation commit damaged the foreign native trail")
			}
		})
	}
}

func TestCFNTrailCreateCommitRechecksTagPermission(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNPrivateTrailFixture(t, backend)
			user := f.user(t)
			r := cfnPrivateTrailRequest()
			r.CloudControl = true
			f.destination.after = func() {
				f.native(t, "iam", "PutUserPolicy", map[string]any{"UserName": "trail-owner", "PolicyName": "deny-tags", "PolicyDocument": `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"cloudtrail:AddTags","Resource":"*"}}`})
			}
			out, err := f.h.Create(user, r)
			if err == nil || out.PhysicalID != "" {
				t.Fatalf("create admitted tags under revoked permission: %+v %v", out, err)
			}
			out, err = f.h.RecoverCreation(f.ctx, r)
			if !cfnTrailMissing(err) || out.PhysicalID != "" {
				t.Fatalf("rejected create retained a partial private claim: %+v %v", out, err)
			}
			_, err = cfnComputeCall[trailapi.GetTrailOutput](f.ctx, f.commands, "cloudtrail", "GetTrail", map[string]any{"Name": "private-trail"})
			var wire *awswire.Error
			if !errors.As(err, &wire) || wire.Code != "TrailNotFoundException" {
				t.Fatalf("tag admission failure persisted native state: %v", err)
			}
		})
	}
}

func TestCFNTrailEveryNativeMutationChecksActualPrivateClaim(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNPrivateTrailFixture(t, backend)
			r := cfnPrivateTrailRequest()
			created, err := f.h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			foreign := r
			foreign.Token = "counterfeit-incarnation"
			f.native(t, "cloudtrail", "AddTags", map[string]any{"ResourceId": "private-trail", "TagsList": cfnComputeTagList(cfnComputeOwnedTags(foreign))})
			ctx := cloudtrail.WithCloudFormationOwner(f.ctx, cfnLogsMarker(foreign), false)
			before := f.row(t)
			for _, mutation := range []struct {
				operation string
				input     map[string]any
			}{
				{"UpdateTrail", map[string]any{"Name": "private-trail", "S3KeyPrefix": "counterfeit"}},
				{"PutEventSelectors", map[string]any{"TrailName": "private-trail", "EventSelectors": []any{map[string]any{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": true}}}},
				{"StartLogging", map[string]any{"Name": "private-trail"}},
				{"StopLogging", map[string]any{"Name": "private-trail"}},
				{"AddTags", map[string]any{"ResourceId": "private-trail", "TagsList": []any{map[string]any{"Key": "team", "Value": "counterfeit"}}}},
				{"RemoveTags", map[string]any{"ResourceId": "private-trail", "TagsList": []any{map[string]any{"Key": "team"}}}},
				{"DeleteTrail", map[string]any{"Name": "private-trail"}},
			} {
				if err := cfnComputeRun(ctx, f.commands, "cloudtrail", mutation.operation, mutation.input); err == nil {
					t.Fatalf("%s trusted counterfeit public tags", mutation.operation)
				}
				if after := f.row(t); !reflect.DeepEqual(before, after) {
					t.Fatalf("%s changed the actual native trail after rejecting its private claim", mutation.operation)
				}
			}
			f.native(t, "cloudtrail", "UpdateTrail", map[string]any{"Name": "private-trail", "S3KeyPrefix": "native-change"})
			if f.row(t).CFNOwner != before.CFNOwner {
				t.Fatal("direct native update rewrote private ownership")
			}
			if _, err := f.h.Update(f.ctx, r); err != nil {
				t.Fatalf("authentic private update was revoked by forged tags: %v", err)
			}
			read, err := f.h.Read(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			listed, err := f.h.List(f.ctx, r)
			if err != nil || len(listed) != 1 {
				t.Fatalf("native list failed: %+v %v", listed, err)
			}
			for _, model := range []cloudformation.Properties{read, listed[0].Properties} {
				for key := range model {
					if strings.Contains(strings.ToLower(key), "cfnowner") {
						t.Fatalf("private claim appeared in public model: %s", key)
					}
				}
				if !reflect.DeepEqual(model["Tags"], []any{map[string]any{"Key": "team", "Value": "original"}}) {
					t.Fatalf("claim tags appeared in Read/List: %#v", model["Tags"])
				}
			}
		})
	}
}
