package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/firehose"
	"stackd/internal/services/iam"
	"stackd/internal/services/s3"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	firehosestore "stackd/storage/sqlite/firehose"
)

type cfnWorkflowFirehoseFixture struct {
	ctx    context.Context
	clock  *clock.Manual
	owner  *firehose.Service
	config firehose.Config
	h      cfnDeliveryStream
}

func cfnWorkflowFirehose(t *testing.T, repository firehose.Repository) *cfnWorkflowFirehoseFixture {
	t.Helper()
	ctx := cfnWorkflowOwnerContext(t)
	source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
	domain := memory.NewDomain()
	identities := iam.NewMemoryRepository(domain)
	role := iam.Role{Arn: "arn:aws:iam::123456789012:role/firehose-workflow", RoleName: "firehose-workflow", RoleId: "AROAFIREHOSEWORKFLOW", MaxSessionDuration: 3600,
		AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"firehose.amazonaws.com"},"Action":"sts:AssumeRole"}}`,
		IdentityPolicies:         iam.IdentityPolicies{Inline: map[string]string{"destination": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`}}}
	if err := identities.Update(ctx, func(tx iam.WriteTx) error {
		return tx.PutRole(iam.Scope{Partition: "aws", AccountID: "123456789012"}, role)
	}); err != nil {
		t.Fatal(err)
	}
	credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(identities, nil), Clock: source})
	identityOwner := iam.NewWithConfig(iam.Config{Repository: identities, Credentials: credentials, Clock: source})
	authorizer := authorization.NewWithClock(identityOwner, nil, source)
	buckets := s3.New(s3.Config{Repository: s3.NewMemoryRepository(domain), Clock: source, Authorizer: authorizer})
	t.Cleanup(func() { _ = buckets.Close(); _ = identityOwner.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"s3": buckets})
	if err := cfnComputeRun(ctx, commands, "s3", "CreateBucket", map[string]any{"Bucket": "workflow-firehose"}); err != nil {
		t.Fatal(err)
	}
	destination := &FirehoseS3{Roles: ServiceRoles{IAM: identityOwner, Credentials: credentials, Authorizer: authorizer}, S3: buckets, Clock: source}
	config := firehose.Config{Repository: repository, Clock: source, Authorizer: authorizer, Destination: destination}
	f := &cfnWorkflowFirehoseFixture{ctx: ctx, clock: source, config: config}
	f.assemble()
	t.Cleanup(func() { _ = f.owner.Close() })
	return f
}
func (f *cfnWorkflowFirehoseFixture) assemble() {
	f.owner = firehose.New(f.config)
	f.h = cfnDeliveryStream{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"firehose": f.owner})}
}
func cfnWorkflowStreamProperties() cloudformation.Properties {
	return cloudformation.Properties{"DeliveryStreamName": "workflow-firehose", "ExtendedS3DestinationConfiguration": map[string]any{"BucketARN": "arn:aws:s3:::workflow-firehose", "RoleARN": "arn:aws:iam::123456789012:role/firehose-workflow", "Prefix": "initial/"}, "Tags": []any{map[string]any{"Key": "team", "Value": "initial"}}}
}
func TestCFNFirehoseEncryptionUpdateFailsBeforeEffects(t *testing.T) {
	f := cfnWorkflowFirehose(t, nil)
	r := cfnWorkflowOwnerRequest("AWS::KinesisFirehose::DeliveryStream", "Stream", cfnWorkflowStreamProperties())
	created, err := f.h.Create(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = created.PhysicalID
	if err := f.clock.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.JobDriver().RunDue(f.ctx, 10); err != nil {
		t.Fatal(err)
	}
	before, err := f.h.describe(f.ctx, r.PhysicalID)
	if err != nil {
		t.Fatal(err)
	}
	tags, err := f.h.tags(f.ctx, r.PhysicalID)
	if err != nil {
		t.Fatal(err)
	}
	r.Previous = r.Properties
	r.Properties = cfnWorkflowStreamProperties()
	r.Properties["DeliveryStreamEncryptionConfigurationInput"] = map[string]any{"KeyType": "AWS_OWNED_CMK"}
	r.Properties["ExtendedS3DestinationConfiguration"].(map[string]any)["Prefix"] = "must-not-change/"
	r.Properties["Tags"] = []any{map[string]any{"Key": "team", "Value": "must-not-change"}}
	for _, cc := range []bool{false, true} {
		r.CloudControl = cc
		if _, err := f.h.Update(f.ctx, r); err == nil {
			t.Fatal("unsupported encryption update reported success")
		}
		after, err := f.h.describe(f.ctx, r.PhysicalID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("rejected encryption update mutated native destination/version: before=%#v after=%#v", before, after)
		}
		current, err := f.h.tags(f.ctx, r.PhysicalID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(tags, current) {
			t.Fatalf("rejected encryption update changed tags/claims: %#v", current)
		}
	}
}

type cfnWorkflowLostFirehoseReply struct {
	*firehose.Service
	lose bool
}

func (e *cfnWorkflowLostFirehoseReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.Service.ExecuteCommand(ctx, r)
	if err == nil && e.lose && string(r.Operation.Name) == "CreateDeliveryStream" {
		e.lose = false
		return nil, &awswire.Error{Code: "InvalidArgumentException", Message: "lost admitted create reply", StatusCode: 400}
	}
	return out, err
}
func TestCFNFirehoseAdmittedErrorRetainsPrivateIncarnation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := cfnWorkflowOwnerContext(t)
			var repository firehose.Repository = firehose.NewMemoryRepository(nil)
			var db *sql.DB
			path := filepath.Join(t.TempDir(), "firehose.sqlite")
			open := func() {
				var err error
				db, err = sqlite.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				repository = firehosestore.New(db)
			}
			if backend == "sqlite" {
				open()
				t.Cleanup(func() { _ = db.Close() })
			}
			f := cfnWorkflowFirehose(t, repository)
			executor := &cfnWorkflowLostFirehoseReply{Service: f.owner, lose: true}
			f.h = cfnDeliveryStream{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"firehose": executor})}
			r := cfnWorkflowOwnerRequest("AWS::KinesisFirehose::DeliveryStream", "CCStream", cfnWorkflowStreamProperties())
			r.CloudControl = true
			created, err := f.h.Create(f.ctx, r)
			if err == nil || created.PhysicalID != "workflow-firehose" {
				t.Fatalf("lost modeled reply discarded admitted stream ID: %+v %v", created, err)
			}
			if backend == "sqlite" {
				if err := f.owner.Close(); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				open()
				f.config.Repository = repository
				f.assemble()
			}
			recovered, err := f.h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("private create claim did not survive recovery: %+v %v", recovered, err)
			}
			replayed, err := f.h.Create(f.ctx, r)
			if err != nil || replayed.PhysicalID != created.PhysicalID {
				t.Fatalf("same-token CC replay changed ownership: %+v %v", replayed, err)
			}
			foreign := r
			foreign.Token = "foreign-incarnation"
			if err := cfnComputeRun(f.ctx, f.h.commands, "firehose", "TagDeliveryStream", map[string]any{"DeliveryStreamName": created.PhysicalID, "Tags": cfnComputeTagList(map[string]string{"stackd:cloudformation:owner": cfnMessagingOwner(foreign), "stackd:cloudformation:create-token": cfnMessagingHash(foreign.Token)})}); err != nil {
				t.Fatal(err)
			}
			rejected, err := f.h.Create(f.ctx, foreign)
			if err == nil || rejected.PhysicalID != "" {
				t.Fatalf("foreign CC create adopted stream: %+v %v", rejected, err)
			}
			rejected, err = f.h.RecoverCreation(f.ctx, foreign)
			if err == nil || rejected.PhysicalID != "" {
				t.Fatalf("public tags forged native recovery claim: %+v %v", rejected, err)
			}
			r.PhysicalID = created.PhysicalID
			// Native Firehose permits deleting the exact admitted CREATING owner for rollback.
			if err := f.h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := f.clock.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := f.owner.JobDriver().RunDue(f.ctx, 10); err != nil {
				t.Fatal(err)
			}
			if _, err := f.h.RecoverCreation(f.ctx, r); !cfnComputeMissing(err) {
				t.Fatalf("rollback failed to delete admitted stream: %v", err)
			}
		})
	}
}
