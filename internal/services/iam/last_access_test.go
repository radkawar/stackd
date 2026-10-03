package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

func finishAccessReport(t *testing.T, service *iam.Service, source *clock.Manual, client *sdkiam.Client, id *string) *sdkiam.GetServiceLastAccessedDetailsOutput {
	t.Helper()
	source.Advance(time.Second)
	if _, err := service.RunDueJobs(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	out, err := client.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: id})
	if err != nil {
		t.Fatal(err)
	}
	if out.JobStatus != types.JobStatusTypeCompleted || out.JobCompletionDate == nil {
		t.Fatalf("report not completed: %+v", out)
	}
	return out
}

func TestAccessReportSignedActivitySnapshotAndOwnership(t *testing.T) {
	start := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	f := newActivityFixture(t, nil, start)
	key := f.user(t, "report-subject")
	_, err := f.root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: aws.String("report-subject"), PolicyName: aws.String("Conditional"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/missing":"yes"}}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.client("eu-west-1", key).GetUser(t.Context(), &sdkiam.GetUserInput{})
	requireCode(t, err, "AccessDenied")
	generated, err := f.root.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: aws.String(key.PrincipalARN), Granularity: types.AccessAdvisorUsageGranularityTypeActionLevel})
	if err != nil {
		t.Fatal(err)
	}
	// The snapshot belongs to acceptance, even if permissions change before
	// the asynchronous job becomes readable.
	_, err = f.root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: aws.String("report-subject"), PolicyName: aws.String("PendingChange"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"sns:Publish","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.root.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	if err != nil {
		t.Fatal(err)
	}
	if pending.JobStatus != types.JobStatusTypeInProgress || pending.JobCompletionDate != nil || pending.ServicesLastAccessed != nil || pending.JobType != "" {
		t.Fatalf("pending shape=%+v", pending)
	}
	entitiesPending, err := f.root.GetServiceLastAccessedDetailsWithEntities(t.Context(), &sdkiam.GetServiceLastAccessedDetailsWithEntitiesInput{JobId: generated.JobId, ServiceNamespace: aws.String("iam")})
	if err != nil || entitiesPending.JobCompletionDate != nil || entitiesPending.EntityDetailsList != nil {
		t.Fatalf("pending entities=%+v error=%v", entitiesPending, err)
	}
	out := finishAccessReport(t, f.service, f.clock, f.root, generated.JobId)
	if len(out.ServicesLastAccessed) != 1 {
		t.Fatalf("service list=%+v", out.ServicesLastAccessed)
	}
	service := out.ServicesLastAccessed[0]
	if aws.ToString(service.ServiceName) != "AWS Identity and Access Management" || aws.ToString(service.ServiceNamespace) != "iam" || service.LastAuthenticated == nil || !service.LastAuthenticated.Equal(start) || aws.ToString(service.LastAuthenticatedEntity) != key.PrincipalARN || aws.ToString(service.LastAuthenticatedRegion) != "eu-west-1" || aws.ToInt32(service.TotalAuthenticatedEntities) != 1 {
		t.Fatalf("service activity=%+v", service)
	}
	if len(service.TrackedActionsLastAccessed) != 1 || aws.ToString(service.TrackedActionsLastAccessed[0].ActionName) != "GetUser" || service.TrackedActionsLastAccessed[0].LastAccessedTime == nil {
		t.Fatalf("action activity=%+v", service.TrackedActionsLastAccessed)
	}
	entities, err := f.root.GetServiceLastAccessedDetailsWithEntities(t.Context(), &sdkiam.GetServiceLastAccessedDetailsWithEntitiesInput{JobId: generated.JobId, ServiceNamespace: aws.String("iam")})
	if err != nil || len(entities.EntityDetailsList) != 1 || aws.ToString(entities.EntityDetailsList[0].EntityInfo.Id) != key.PrincipalID || entities.EntityDetailsList[0].LastAuthenticated == nil {
		t.Fatalf("entities=%+v err=%v", entities, err)
	}
	// Another fully authorized user still cannot retrieve this caller's job.
	observer := f.user(t, "report-observer")
	_, err = f.root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: aws.String("report-observer"), PolicyName: aws.String("Reports"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.client("us-east-1", observer).GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	requireCode(t, err, "NoSuchEntity")
	// Later policy changes and activity never rewrite a completed snapshot.
	snapshot, _ := json.Marshal(out.ServicesLastAccessed)
	_, err = f.root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: aws.String("report-subject"), PolicyName: aws.String("Conditional"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":["iam:GetUser","sqs:SendMessage"],"Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.client("us-east-1", key).GetUser(t.Context(), &sdkiam.GetUserInput{})
	if err != nil {
		t.Fatal(err)
	}
	reread, err := f.root.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(reread.ServicesLastAccessed)
	if string(snapshot) != string(after) {
		t.Fatalf("completed report changed: %s -> %s", snapshot, after)
	}
	if _, err := f.root.DeleteUserPolicy(t.Context(), &sdkiam.DeleteUserPolicyInput{UserName: aws.String("report-subject"), PolicyName: aws.String("PendingChange")}); err != nil {
		t.Fatal(err)
	}
	newer, err := f.root.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: aws.String(key.PrincipalARN)})
	if err != nil {
		t.Fatal(err)
	}
	current := finishAccessReport(t, f.service, f.clock, f.root, newer.JobId)
	if len(current.ServicesLastAccessed) != 2 {
		t.Fatalf("new permissions absent: %+v", current.ServicesLastAccessed)
	}
}

func TestAccessReportGroupPolicyPaginationAndDeletion(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
	service := iam.NewWithConfig(iam.Config{Clock: source})
	t.Cleanup(func() { _ = service.Close() })
	root := clientFor(t, service, "123456789012", "us-east-1")
	policy, err := root.CreatePolicy(t.Context(), &sdkiam.CreatePolicyInput{PolicyName: aws.String("AccessReportPolicy"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":["s3:GetObject","sqs:SendMessage","iam:GetUser","iam:PassRole"],"Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	group, err := root.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String("AccessReportGroup"), Path: aws.String("/reports/")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.AttachGroupPolicy(t.Context(), &sdkiam.AttachGroupPolicyInput{GroupName: group.Group.GroupName, PolicyArn: policy.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ReportA", "ReportB"} {
		if _, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
		if _, err := root.AddUserToGroup(t.Context(), &sdkiam.AddUserToGroupInput{GroupName: group.Group.GroupName, UserName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	generated, err := root.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: policy.Policy.Arn, Granularity: types.AccessAdvisorUsageGranularityTypeActionLevel})
	if err != nil {
		t.Fatal(err)
	}
	out := finishAccessReport(t, service, source, root, generated.JobId)
	var namespaces []string
	for _, entry := range out.ServicesLastAccessed {
		namespaces = append(namespaces, aws.ToString(entry.ServiceNamespace))
		if entry.LastAuthenticated != nil || aws.ToInt32(entry.TotalAuthenticatedEntities) != 0 {
			t.Fatalf("invented activity=%+v", entry)
		}
	}
	if !slices.Equal(namespaces, []string{"iam", "s3", "sqs"}) {
		t.Fatalf("namespaces=%v", namespaces)
	}
	if len(out.ServicesLastAccessed[0].TrackedActionsLastAccessed) != 1 || aws.ToString(out.ServicesLastAccessed[0].TrackedActionsLastAccessed[0].ActionName) != "GetUser" || len(out.ServicesLastAccessed[1].TrackedActionsLastAccessed) != 0 || len(out.ServicesLastAccessed[2].TrackedActionsLastAccessed) != 0 {
		t.Fatalf("tracked actions=%+v", out.ServicesLastAccessed)
	}
	first, err := root.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId, MaxItems: aws.Int32(1)})
	if err != nil || !first.IsTruncated || first.Marker == nil {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	rest, err := root.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId, MaxItems: aws.Int32(100), Marker: first.Marker})
	if err != nil || rest.IsTruncated || len(rest.ServicesLastAccessed) != 2 {
		t.Fatalf("rest=%+v err=%v", rest, err)
	}
	entities, err := root.GetServiceLastAccessedDetailsWithEntities(t.Context(), &sdkiam.GetServiceLastAccessedDetailsWithEntitiesInput{JobId: generated.JobId, ServiceNamespace: aws.String("s3"), MaxItems: aws.Int32(1)})
	if err != nil || !entities.IsTruncated || len(entities.EntityDetailsList) != 1 || entities.EntityDetailsList[0].LastAuthenticated != nil {
		t.Fatalf("entities=%+v err=%v", entities, err)
	}
	last, err := root.GetServiceLastAccessedDetailsWithEntities(t.Context(), &sdkiam.GetServiceLastAccessedDetailsWithEntitiesInput{JobId: generated.JobId, ServiceNamespace: aws.String("sqs"), Marker: entities.Marker})
	if err != nil || last.IsTruncated || len(last.EntityDetailsList) != 1 || aws.ToString(last.EntityDetailsList[0].EntityInfo.Name) != "ReportB" {
		t.Fatalf("cross namespace cursor=%+v err=%v", last, err)
	}
	_, err = root.GetServiceLastAccessedDetailsWithEntities(t.Context(), &sdkiam.GetServiceLastAccessedDetailsWithEntitiesInput{JobId: generated.JobId, ServiceNamespace: aws.String("s3"), Marker: first.Marker})
	requireCode(t, err, "InvalidInput")
	// Completed policy reports survive detachment and deletion of their source.
	if _, err := root.DetachGroupPolicy(t.Context(), &sdkiam.DetachGroupPolicyInput{GroupName: group.Group.GroupName, PolicyArn: policy.Policy.Arn}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.DeletePolicy(t.Context(), &sdkiam.DeletePolicyInput{PolicyArn: policy.Policy.Arn}); err != nil {
		t.Fatal(err)
	}
	reread, err := root.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	if err != nil || len(reread.ServicesLastAccessed) != 3 {
		t.Fatalf("deleted-source report=%+v err=%v", reread, err)
	}
	_, err = root.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: policy.Policy.Arn})
	requireCode(t, err, "NoSuchEntity")
}

func TestAccessReportRepositoryRollbackAndDetachedSnapshot(t *testing.T) {
	repo := iam.NewMemoryRepository(nil)
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	report := iam.AccessReport{ID: "job", Services: []iam.ServiceAccess{{Namespace: "iam", Entities: []iam.EntityAccess{{ID: "user", LastActivity: &iam.PrincipalActivity{ActionName: "GetUser"}}}}}}
	canceled := errors.New("abort")
	if err := repo.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := tx.PutAccessReport(scope, report); err != nil {
			return err
		}
		return canceled
	}); !errors.Is(err, canceled) {
		t.Fatal(err)
	}
	if err := repo.View(t.Context(), func(tx iam.ReadTx) error { _, err := tx.AccessReport(scope, "job"); return err }); !errors.Is(err, iam.ErrRecordNotFound) {
		t.Fatalf("aborted report=%v", err)
	}
	if err := repo.Update(t.Context(), func(tx iam.WriteTx) error { return tx.PutAccessReport(scope, report) }); err != nil {
		t.Fatal(err)
	}
	report.Services[0].Entities[0].LastActivity.ActionName = "changed"
	for range 2 {
		if err := repo.View(context.Background(), func(tx iam.ReadTx) error {
			stored, err := tx.AccessReport(scope, "job")
			if err != nil {
				return err
			}
			if stored.Services[0].Entities[0].LastActivity.ActionName != "GetUser" {
				t.Fatal("snapshot alias")
			}
			stored.Services[0].Entities[0].LastActivity.ActionName = "changed"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAccessReportJobSurvivesServiceReconstruction(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
	repo := iam.NewMemoryRepository(nil)
	service := iam.NewWithConfig(iam.Config{Repository: repo, Clock: source})
	root := clientFor(t, service, "123456789012", "us-east-1")
	user, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("RecoverReport")})
	if err != nil {
		t.Fatal(err)
	}
	generated, err := root.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: user.User.Arn})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := iam.NewWithConfig(iam.Config{Repository: repo, Clock: source})
	t.Cleanup(func() { _ = reopened.Close() })
	reader := clientFor(t, reopened, "123456789012", "us-east-1")
	complete := finishAccessReport(t, reopened, source, reader, generated.JobId)
	if len(complete.ServicesLastAccessed) != 0 {
		t.Fatalf("empty user has invented grants: %+v", complete)
	}
	foreign := clientFor(t, reopened, "999999999999", "us-east-1")
	_, err = foreign.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	requireCode(t, err, "NoSuchEntity")
	otherPartition := clientForPartition(t, reopened, "123456789012", "cn-north-1", "aws-cn")
	_, err = otherPartition.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	requireCode(t, err, "NoSuchEntity")
}

func TestAccessReportOwnerUserKeysAndExactRoleSession(t *testing.T) {
	f := newActivityFixture(t, nil, time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
	parent := f.user(t, "report-owner")
	document := `{"Statement":{"Effect":"Allow","Action":["iam:GenerateServiceLastAccessedDetails","iam:GetServiceLastAccessedDetails"],"Resource":"*"}}`
	if _, err := f.root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: aws.String("report-owner"), PolicyName: aws.String("Reports"), PolicyDocument: &document}); err != nil {
		t.Fatal(err)
	}
	first := f.client("us-east-1", parent)
	generated, err := first.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: &parent.PrincipalARN})
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.root.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{UserName: aws.String("report-owner")})
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := f.store.Resolve(t.Context(), aws.ToString(second.AccessKey.AccessKeyId))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client("us-east-1", secondKey).GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId}); err != nil {
		t.Fatalf("same user second key lost ownership: %v", err)
	}
	_, err = f.root.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	requireCode(t, err, "NoSuchEntity")
	role, err := f.root.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("ReportRole"), AssumeRolePolicyDocument: aws.String(trustEC2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.root.PutRolePolicy(t.Context(), &sdkiam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("Reports"), PolicyDocument: &document}); err != nil {
		t.Fatal(err)
	}
	spec := identity.RoleSessionSpec{Role: identity.Principal{AccountID: parent.AccountID, ARN: aws.ToString(role.Role.Arn), ID: aws.ToString(role.Role.RoleId)}, SessionName: "same-name", Duration: time.Hour, MaxSessionDuration: time.Hour}
	// Session issuance is setup; the behavior under test is IAM's signed report
	// requests, including colliding session ARNs issued distinct credentials.
	session1, err := f.store.IssueRoleSession(t.Context(), parent, spec)
	if err != nil {
		t.Fatal(err)
	}
	session2, err := f.store.IssueRoleSession(t.Context(), parent, spec)
	if err != nil {
		t.Fatal(err)
	}
	owner := f.client("us-east-1", session1)
	private, err := owner.GenerateServiceLastAccessedDetails(t.Context(), &sdkiam.GenerateServiceLastAccessedDetailsInput{Arn: role.Role.Arn})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.client("us-east-1", session2).GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: private.JobId})
	requireCode(t, err, "NoSuchEntity")
	if _, err := owner.GetServiceLastAccessedDetails(t.Context(), &sdkiam.GetServiceLastAccessedDetailsInput{JobId: private.JobId}); err != nil {
		t.Fatal(err)
	}
}
