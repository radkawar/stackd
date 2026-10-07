package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	s3api "stackd/internal/awsapi/s3"
	controlapi "stackd/internal/awsapi/s3control"
	"stackd/internal/awscommands"
	"stackd/internal/identity"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/iam"
	"stackd/internal/services/s3"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqls3 "stackd/storage/sqlite/s3"
)

// cfnS3OwnerFixture runs the real S3 and S3 Control owners over memory or a
// reopened SQLite database. Nothing below mocks owner responses.
type cfnS3OwnerFixture struct {
	ctx        context.Context
	backend    string
	path       string
	db         *sql.DB
	repository s3.Repository
	source     clock.Clock
	authorizer authorization.Authorizer
	owner      *s3.Service
	commands   StepFunctionsCommands
}

func newCFNS3OwnerFixture(t *testing.T, backend string) *cfnS3OwnerFixture {
	t.Helper()
	f := &cfnS3OwnerFixture{ctx: cfnWorkflowOwnerContext(t), backend: backend, source: clock.NewManual(time.Date(2032, 3, 4, 5, 6, 0, 0, time.UTC))}
	domain := memory.NewDomain()
	identities := iam.NewMemoryRepository(domain)
	credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(identities, nil), Clock: f.source})
	principals := iam.NewWithConfig(iam.Config{Repository: identities, Credentials: credentials, Clock: f.source})
	f.authorizer = authorization.NewWithClock(principals, nil, f.source)
	f.repository = s3.NewMemoryRepository(domain)
	f.path = filepath.Join(t.TempDir(), "s3.sqlite")
	f.open(t)
	t.Cleanup(func() {
		_ = f.owner.Close()
		_ = principals.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}

func (f *cfnS3OwnerFixture) open(t *testing.T) {
	t.Helper()
	if f.backend == "sqlite" {
		var err error
		if f.db, err = sqlite.Open(f.ctx, f.path); err != nil {
			t.Fatal(err)
		}
		f.repository = sqls3.New(f.db)
	}
	f.owner = s3.New(s3.Config{Repository: f.repository, Authorizer: f.authorizer, Clock: f.source})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"s3": f.owner, "s3control": f.owner.Control()})
}

// reopen proves private claims are durable SQLite columns, not process state.
func (f *cfnS3OwnerFixture) reopen(t *testing.T) {
	t.Helper()
	if f.backend != "sqlite" {
		return
	}
	if err := f.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
}

func (f *cfnS3OwnerFixture) native(t *testing.T, service, operation string, input map[string]any) {
	t.Helper()
	if err := cfnComputeRun(f.ctx, f.commands, service, operation, input); err != nil {
		t.Fatalf("%s.%s: %v", service, operation, err)
	}
}

// counterfeit writes every historical public marker through the real native tag
// API; private ownership cannot be reconstructed from these bytes.
func (f *cfnS3OwnerFixture) counterfeit(t *testing.T, bucket string, victim cloudformation.ResourceRequest) {
	t.Helper()
	tags := cfnComputeOwnedTags(victim)
	tags[cfnMessagingOwnerTag], tags[cfnMessagingTokenTag] = cfnMessagingOwner(victim), cfnMessagingHash(victim.Token)
	set := []map[string]string{}
	for _, key := range cfnMessagingKeys(tags) {
		set = append(set, map[string]string{"Key": key, "Value": tags[key]})
	}
	f.native(t, "s3", "PutBucketTagging", map[string]any{"Bucket": bucket, "Tagging": map[string]any{"TagSet": set}})
}

func (f *cfnS3OwnerFixture) bucketExists(t *testing.T, bucket string) bool {
	t.Helper()
	_, err := cfnComputeCall[s3api.GetBucketLocationOutput](f.ctx, f.commands, "s3", "GetBucketLocation", map[string]any{"Bucket": bucket})
	if cfnMessagingMissing(err, "NoSuchBucket") {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

func cfnS3OwnerAbsent(err error) bool {
	return cfnMessagingMissing(err, "NotFound", "NoSuchBucket")
}

func TestCFNS3BucketPrivateOwnerRejectsCounterfeitAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNS3OwnerFixture(t, backend)
			r := cfnWorkflowOwnerRequest("AWS::S3::Bucket", "Logs", cloudformation.Properties{"BucketName": "owned-logs", "Tags": []any{map[string]any{"Key": "team", "Value": "storage"}}})
			created, err := cfnS3Bucket{f.commands}.Create(f.ctx, r)
			if err != nil || created.PhysicalID != "owned-logs" {
				t.Fatalf("create: %+v %v", created, err)
			}
			r.PhysicalID = created.PhysicalID
			f.reopen(t)
			h := cfnS3Bucket{f.commands}
			if recovered, err := h.RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("private claim did not survive reopen: %+v %v", recovered, err)
			}
			if replayed, err := h.Create(f.ctx, r); err != nil || replayed.PhysicalID != created.PhysicalID {
				t.Fatalf("same-token replay: %+v %v", replayed, err)
			}

			// A direct-API bucket carrying every public stack marker of a
			// stack incarnation is never adopted, observed or deleted by it.
			f.native(t, "s3", "CreateBucket", map[string]any{"Bucket": "forged-logs"})
			forged := cfnWorkflowOwnerRequest("AWS::S3::Bucket", "Forged", cloudformation.Properties{"BucketName": "forged-logs"})
			f.counterfeit(t, "forged-logs", forged)
			if adopted, err := h.Create(f.ctx, forged); err == nil || adopted.PhysicalID != "" {
				t.Fatalf("counterfeit markers adopted a bucket: %+v %v", adopted, err)
			}
			cc := forged
			cc.CloudControl = true
			if _, err := h.Create(f.ctx, cc); !cfnMessagingMissing(err, "AlreadyExistsException") {
				t.Fatalf("Cloud Control create adopted a counterfeit bucket: %v", err)
			}
			if recovered, err := h.RecoverCreation(f.ctx, forged); err == nil || cfnS3OwnerAbsent(err) || recovered.PhysicalID != "" {
				t.Fatalf("counterfeit recovery: %+v %v", recovered, err)
			}
			forged.PhysicalID = "forged-logs"
			if err := h.Delete(f.ctx, forged); err == nil || !f.bucketExists(t, "forged-logs") {
				t.Fatalf("counterfeit markers authorized deletion: %v", err)
			}

			// Same-name recreation with copied tags after native deletion is a
			// foreign incarnation for the stale stack resource.
			f.native(t, "s3", "DeleteBucket", map[string]any{"Bucket": "owned-logs"})
			if _, err := h.RecoverCreation(f.ctx, r); !cfnS3OwnerAbsent(err) {
				t.Fatalf("deleted incarnation is not modeled absent: %v", err)
			}
			f.native(t, "s3", "CreateBucket", map[string]any{"Bucket": "owned-logs"})
			f.counterfeit(t, "owned-logs", r)
			f.reopen(t)
			h = cfnS3Bucket{f.commands}
			if recovered, err := h.RecoverCreation(f.ctx, r); err == nil || cfnS3OwnerAbsent(err) || recovered.PhysicalID != "" {
				t.Fatalf("foreign recreation recovered: %+v %v", recovered, err)
			}
			if replayed, err := h.Create(f.ctx, r); err == nil || replayed.PhysicalID != "" {
				t.Fatalf("same-token replay adopted foreign recreation: %+v %v", replayed, err)
			}
			update := r
			update.Previous, update.Properties = r.Properties, cloudformation.Properties{"BucketName": "owned-logs", "VersioningConfiguration": map[string]any{"Status": "Enabled"}}
			if _, err := h.Update(f.ctx, update); err == nil {
				t.Fatal("stale incarnation mutated a foreign recreation")
			}
			versioning, err := cfnComputeCall[s3api.GetBucketVersioningOutput](f.ctx, f.commands, "s3", "GetBucketVersioning", map[string]any{"Bucket": "owned-logs"})
			if err != nil || versioning.Status != nil {
				t.Fatalf("foreign versioning changed: %+v %v", versioning, err)
			}
			if err := h.Delete(f.ctx, r); err == nil || !f.bucketExists(t, "owned-logs") {
				t.Fatalf("stale incarnation deleted a foreign recreation: %v", err)
			}

			// Cloud Control observes customer metadata without granting a claim.
			direct := cloudformation.ResourceRequest{Type: "AWS::S3::Bucket", PhysicalID: "owned-logs", Scope: r.Scope, CloudControl: true}
			_, err = h.Read(f.ctx, direct)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.Delete(f.ctx, direct); err != nil || f.bucketExists(t, "owned-logs") {
				t.Fatalf("native Cloud Control delete: %v", err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatalf("absent bucket: %v", err)
			}
		})
	}
}

func TestCFNS3BucketPolicyEdgeIsPrivatelyOwned(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNS3OwnerFixture(t, backend)
			f.native(t, "s3", "CreateBucket", map[string]any{"Bucket": "policy-target"})
			document := func(action string) map[string]any {
				return map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"Service": "cloudtrail.amazonaws.com"}, "Action": action, "Resource": "arn:aws:s3:::policy-target"}}}
			}
			policy := func() string {
				out, err := cfnComputeCall[s3api.GetBucketPolicyOutput](f.ctx, f.commands, "s3", "GetBucketPolicy", map[string]any{"Bucket": "policy-target"})
				if cfnMessagingMissing(err, "NoSuchBucketPolicy") {
					return ""
				}
				if err != nil {
					t.Fatal(err)
				}
				return string(*out.Policy)
			}
			h := cfnS3BucketPolicy{f.commands}
			r := cfnWorkflowOwnerRequest("AWS::S3::BucketPolicy", "Policy", cloudformation.Properties{"Bucket": "policy-target", "PolicyDocument": document("s3:GetBucketAcl")})
			created, err := h.Create(f.ctx, r)
			if err != nil || created.PhysicalID != "policy-target" {
				t.Fatalf("create: %+v %v", created, err)
			}
			r.PhysicalID = created.PhysicalID
			owned := policy()
			// Bucket tags carry no policy authority: forging them changes nothing.
			f.counterfeit(t, "policy-target", r)
			foreign := cfnWorkflowOwnerRequest("AWS::S3::BucketPolicy", "Other", cloudformation.Properties{"Bucket": "policy-target", "PolicyDocument": document("s3:ListBucket")})
			if adopted, err := h.Create(f.ctx, foreign); err == nil || adopted.PhysicalID != "" || policy() != owned {
				t.Fatalf("another incarnation replaced an owned policy: %+v %v", adopted, err)
			}
			if _, err := h.RecoverCreation(f.ctx, foreign); !cfnS3OwnerAbsent(err) {
				t.Fatalf("foreign incarnation observed this policy: %v", err)
			}
			foreign.PhysicalID = "policy-target"
			if err := h.Delete(f.ctx, foreign); err == nil || policy() != owned {
				t.Fatalf("another incarnation deleted an owned policy: %v", err)
			}
			f.reopen(t)
			h = cfnS3BucketPolicy{f.commands}
			if recovered, err := h.RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != "policy-target" {
				t.Fatalf("policy claim did not survive reopen: %+v %v", recovered, err)
			}
			if replayed, err := h.Create(f.ctx, r); err != nil || replayed.PhysicalID != "policy-target" || policy() != owned {
				t.Fatalf("same-token replay: %+v %v", replayed, err)
			}

			// A public delete ends this edge; a later writer's policy is never
			// adopted, replaced or deleted by the stale incarnation.
			f.native(t, "s3", "DeleteBucketPolicy", map[string]any{"Bucket": "policy-target"})
			if _, err := h.RecoverCreation(f.ctx, r); !cfnS3OwnerAbsent(err) {
				t.Fatalf("publicly deleted edge still observed: %v", err)
			}
			raw, err := cfnMessagingPolicy(document("s3:ListBucket"))
			if err != nil {
				t.Fatal(err)
			}
			f.native(t, "s3", "PutBucketPolicy", map[string]any{"Bucket": "policy-target", "Policy": raw})
			external := policy()
			update := r
			update.Previous, update.Properties = r.Properties, cloudformation.Properties{"Bucket": "policy-target", "PolicyDocument": document("s3:GetBucketLocation")}
			if _, err := h.Update(f.ctx, update); err == nil || policy() != external {
				t.Fatalf("stale incarnation replaced a later policy: %v", err)
			}
			if err := h.Delete(f.ctx, r); err != nil || policy() != external {
				t.Fatalf("stale incarnation deleted a later policy: %v", err)
			}
		})
	}
}

func TestCFNS3AccessPointPrivateOwnerRejectsForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNS3OwnerFixture(t, backend)
			f.native(t, "s3", "CreateBucket", map[string]any{"Bucket": "point-target"})
			exists := func(name string) bool {
				_, err := cfnComputeCall[controlapi.GetAccessPointOutput](f.ctx, f.commands, "s3control", "GetAccessPoint", map[string]any{"AccountId": "123456789012", "Name": name})
				if cfnMessagingMissing(err, "NoSuchAccessPoint") {
					return false
				}
				if err != nil {
					t.Fatal(err)
				}
				return true
			}
			counterfeit := func(name string, victim cloudformation.ResourceRequest) {
				tags := cfnComputeOwnedTags(victim)
				tags[cfnMessagingOwnerTag], tags[cfnMessagingTokenTag] = cfnMessagingOwner(victim), cfnMessagingHash(victim.Token)
				f.native(t, "s3control", "TagResource", map[string]any{"AccountId": "123456789012", "ResourceArn": "arn:aws:s3:us-east-1:123456789012:accesspoint/" + name, "Tags": cfnComputeTagList(tags)})
			}
			h := cfnS3AccessPoint{f.commands}
			r := cfnWorkflowOwnerRequest("AWS::S3::AccessPoint", "Point", cloudformation.Properties{"Name": "owned-point", "Bucket": "point-target"})
			created, err := h.Create(f.ctx, r)
			if err != nil || created.PhysicalID != "owned-point" {
				t.Fatalf("create: %+v %v", created, err)
			}
			r.PhysicalID = created.PhysicalID
			f.reopen(t)
			h = cfnS3AccessPoint{f.commands}
			if recovered, err := h.RecoverCreation(f.ctx, r); err != nil || recovered.Attributes["Alias"] != created.Attributes["Alias"] {
				t.Fatalf("private claim did not survive reopen: %+v %v", recovered, err)
			}
			if replayed, err := h.Create(f.ctx, r); err != nil || replayed.Attributes["Alias"] != created.Attributes["Alias"] {
				t.Fatalf("same-token replay: %+v %v", replayed, err)
			}

			f.native(t, "s3control", "CreateAccessPoint", map[string]any{"AccountId": "123456789012", "Name": "forged-point", "Bucket": "point-target"})
			forged := cfnWorkflowOwnerRequest("AWS::S3::AccessPoint", "Forged", cloudformation.Properties{"Name": "forged-point", "Bucket": "point-target"})
			counterfeit("forged-point", forged)
			if adopted, err := h.Create(f.ctx, forged); err == nil || adopted.PhysicalID != "" {
				t.Fatalf("counterfeit markers adopted an access point: %+v %v", adopted, err)
			}
			if _, err := h.RecoverCreation(f.ctx, forged); err == nil || cfnS3OwnerAbsent(err) {
				t.Fatalf("counterfeit recovery: %v", err)
			}
			forged.PhysicalID = "forged-point"
			if err := h.Delete(f.ctx, forged); err == nil || !exists("forged-point") {
				t.Fatalf("counterfeit markers authorized deletion: %v", err)
			}

			f.native(t, "s3control", "DeleteAccessPoint", map[string]any{"AccountId": "123456789012", "Name": "owned-point"})
			if _, err := h.RecoverCreation(f.ctx, r); !cfnS3OwnerAbsent(err) {
				t.Fatalf("deleted incarnation is not modeled absent: %v", err)
			}
			f.native(t, "s3control", "CreateAccessPoint", map[string]any{"AccountId": "123456789012", "Name": "owned-point", "Bucket": "point-target"})
			counterfeit("owned-point", r)
			f.reopen(t)
			h = cfnS3AccessPoint{f.commands}
			if _, err := h.RecoverCreation(f.ctx, r); err == nil || cfnS3OwnerAbsent(err) {
				t.Fatalf("foreign recreation recovered: %v", err)
			}
			update := r
			update.Previous, update.Properties = r.Properties, cloudformation.Properties{"Name": "owned-point", "Bucket": "point-target", "Tags": []any{map[string]any{"Key": "team", "Value": "storage"}}}
			if _, err := h.Update(f.ctx, update); err == nil {
				t.Fatal("stale incarnation mutated a foreign recreation")
			}
			if err := h.Delete(f.ctx, r); err == nil || !exists("owned-point") {
				t.Fatalf("stale incarnation deleted a foreign recreation: %v", err)
			}
			direct := cloudformation.ResourceRequest{Type: "AWS::S3::AccessPoint", PhysicalID: "owned-point", Scope: r.Scope, CloudControl: true}
			if err := h.Delete(f.ctx, direct); err != nil || exists("owned-point") {
				t.Fatalf("native Cloud Control delete: %v", err)
			}
		})
	}
}
