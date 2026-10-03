package stackd_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

type organizationReportFixture struct {
	cloud    cloudClients
	clock    *clock.Manual
	org      *organizations.Client
	iam      *iam.Client
	rootID   string
	rootPath string
}

func newOrganizationReportFixture(t *testing.T, backends *storage.Backends) organizationReportFixture {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
	return organizationFixture(t, c, source)
}

func organizationFixture(t *testing.T, c cloudClients, source *clock.Manual) organizationReportFixture {
	t.Helper()
	org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	created, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll})
	if err != nil {
		t.Fatal(err)
	}
	roots, err := org.ListRoots(t.Context(), &organizations.ListRootsInput{})
	if err != nil {
		t.Fatal(err)
	}
	rootID := aws.ToString(roots.Roots[0].Id)
	return organizationReportFixture{cloud: c, clock: source, org: org, iam: c.iam("test", "test", ""), rootID: rootID, rootPath: aws.ToString(created.Organization.Id) + "/" + rootID}
}

func (f organizationReportFixture) unit(t *testing.T, parent, name string) string {
	t.Helper()
	out, err := f.org.CreateOrganizationalUnit(t.Context(), &organizations.CreateOrganizationalUnitInput{ParentId: &parent, Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.OrganizationalUnit.Id)
}

func (f organizationReportFixture) account(t *testing.T, parent, name string) string {
	t.Helper()
	out, err := f.org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: &name, Email: aws.String(name + "@example.test")})
	if err != nil {
		t.Fatal(err)
	}
	out.CreateAccountStatus = waitAccountCreation(t, f.org, out.CreateAccountStatus, f.clock)
	id := aws.ToString(out.CreateAccountStatus.AccountId)
	if parent != f.rootID {
		_, err = f.org.MoveAccount(t.Context(), &organizations.MoveAccountInput{AccountId: &id, SourceParentId: &f.rootID, DestinationParentId: &parent})
		if err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func (f organizationReportFixture) policy(t *testing.T, name, document, target string) string {
	t.Helper()
	out, err := f.org.CreatePolicy(t.Context(), &organizations.CreatePolicyInput{Name: &name, Description: aws.String("Organization report integration"), Content: &document, Type: orgtypes.PolicyTypeServiceControlPolicy})
	if err != nil {
		t.Fatal(err)
	}
	id := aws.ToString(out.Policy.PolicySummary.Id)
	if target != "" {
		_, err = f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: &id, TargetId: &target})
		if err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func (f organizationReportFixture) generate(t *testing.T, path, policy string) *string {
	t.Helper()
	in := &iam.GenerateOrganizationsAccessReportInput{EntityPath: &path}
	if policy != "" {
		in.OrganizationsPolicyId = &policy
	}
	out, err := f.iam.GenerateOrganizationsAccessReport(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	return out.JobId
}

func finishOrganizationReport(t *testing.T, source *clock.Manual, client *iam.Client, id *string) *iam.GetOrganizationsAccessReportOutput {
	t.Helper()
	advanceClock(t, source, time.Second)
	// The service clock drives eligibility. HTTP reads yield to the automatic
	// worker; the deadline only diagnoses a worker that fails to make progress.
	deadline := time.Now().Add(5 * time.Second)
	for {
		out, err := client.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: id, MaxItems: aws.Int32(1000)})
		if err != nil {
			t.Fatal(err)
		}
		if out.JobStatus != iamtypes.JobStatusTypeInProgress {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatal("Organizations report worker did not complete")
		}
	}
}

func organizationNamespaces(out *iam.GetOrganizationsAccessReportOutput) []string {
	names := make([]string, 0, len(out.AccessDetails))
	for _, row := range out.AccessDetails {
		names = append(names, aws.ToString(row.ServiceNamespace))
	}
	return names
}

func TestOrganizationsAccessReportAggregatesSignedAttemptsAndFreezesHierarchy(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			testOrganizationsAccessReportAggregatesSignedAttemptsAndFreezesHierarchy(t, backend)
		})
	}
}

func testOrganizationsAccessReportAggregatesSignedAttemptsAndFreezesHierarchy(t *testing.T, backend string) {
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
	}
	f := newOrganizationReportFixture(t, backends)
	parent := f.unit(t, f.rootID, "reports")
	child := f.unit(t, parent, "nested")
	first := f.account(t, parent, "report-first")
	second := f.account(t, child, "report-second")
	outside := f.account(t, f.rootID, "report-outside")
	policy := f.policy(t, "AllowedServices", allow(`["iam:*","sqs:*","kms:*","s3:*"]`, "*"), parent)
	if _, err := f.org.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: aws.String("p-FullAWSAccess"), TargetId: &parent}); err != nil {
		t.Fatal(err)
	}
	// A child deny affects actual requests without narrowing a report about
	// the parent OU, whose potential services use that OU and its ancestors.
	f.policy(t, "ChildDeny", `{"Statement":{"Effect":"Deny","Action":"sqs:*","Resource":"*"}}`, child)
	_, key, secret := f.cloud.user(t, first, "denied-producer")
	_, err := f.cloud.sqs(key, secret, "").ListQueues(t.Context(), &sqs.ListQueuesInput{})
	assertAPIError(t, err, "AccessDenied")
	if _, err := f.cloud.sqs(first, "test", "").ListQueues(t.Context(), &sqs.ListQueuesInput{}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, f.clock, time.Minute)
	kmsClient := kms.New(kms.Options{Region: "eu-west-1", BaseEndpoint: aws.String(f.cloud.server.URL), Credentials: credentials.NewStaticCredentialsProvider(second, "test", ""), HTTPClient: f.cloud.server.Client(), RetryMaxAttempts: 1})
	if _, err := kmsClient.ListAliases(t.Context(), &kms.ListAliasesInput{}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, f.clock, time.Minute)
	_, err = f.cloud.sqs(second, "test", "").ListQueues(t.Context(), &sqs.ListQueuesInput{})
	assertAPIError(t, err, "AccessDenied")
	lastSQS := f.clock.Now()
	advanceClock(t, f.clock, time.Minute)
	for _, id := range []string{outside, "test"} {
		if _, err := f.cloud.sqs(id, "test", "").ListQueues(t.Context(), &sqs.ListQueuesInput{}); err != nil {
			t.Fatal(err)
		}
	}
	path := f.rootPath + "/" + parent
	job := f.generate(t, path, "")
	pending, err := f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: job})
	if err != nil || pending.JobStatus != iamtypes.JobStatusTypeInProgress || pending.AccessDetails != nil || pending.JobCompletionDate != nil || pending.NumberOfServicesAccessible != nil {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	// Change both SCPs and membership before processing. Accepted report data
	// must remain bound to the captured hierarchy and authenticated attempts.
	if _, err := f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &policy, Content: aws.String(allow(`"iam:*"`, "*"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.org.MoveAccount(t.Context(), &organizations.MoveAccountInput{AccountId: &second, SourceParentId: &child, DestinationParentId: &f.rootID}); err != nil {
		t.Fatal(err)
	}
	out := finishOrganizationReport(t, f.clock, f.iam, job)
	if out.JobStatus != iamtypes.JobStatusTypeCompleted || !slices.Equal(organizationNamespaces(out), []string{"iam", "kms", "s3", "sqs"}) || aws.ToInt32(out.NumberOfServicesAccessible) != 4 || aws.ToInt32(out.NumberOfServicesNotAccessed) != 1 {
		t.Fatalf("report=%+v", out)
	}
	rows := make(map[string]iamtypes.AccessDetail)
	for _, row := range out.AccessDetails {
		rows[aws.ToString(row.ServiceNamespace)] = row
	}
	sqsRow := rows["sqs"]
	if aws.ToInt32(sqsRow.TotalAuthenticatedEntities) != 2 || aws.ToString(sqsRow.EntityPath) != path+"/"+child+"/"+second || !aws.ToTime(sqsRow.LastAuthenticatedTime).Equal(lastSQS) {
		t.Fatalf("account aggregation=%+v", sqsRow)
	}
	if aws.ToInt32(rows["kms"].TotalAuthenticatedEntities) != 1 || aws.ToString(rows["kms"].Region) != "eu-west-1" || rows["s3"].LastAuthenticatedTime != nil || rows["s3"].EntityPath != nil {
		t.Fatalf("activity rows=%+v", rows)
	}
	before, _ := json.Marshal(out.AccessDetails)
	if _, err := f.cloud.sqs(first, "test", "").ListQueues(t.Context(), &sqs.ListQueuesInput{}); err == nil {
		t.Fatal("updated parent SCP did not deny request")
	}
	after, err := f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: job})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(after.AccessDetails)
	if string(before) != string(encoded) {
		t.Fatal("completed report changed")
	}
	firstPage, err := f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: job, MaxItems: aws.Int32(1), SortKey: iamtypes.SortKeyTypeServiceNamespaceDescending})
	if err != nil || !firstPage.IsTruncated || !slices.Equal(organizationNamespaces(firstPage), []string{"sqs"}) || aws.ToInt32(firstPage.NumberOfServicesAccessible) != 4 {
		t.Fatalf("first page=%+v err=%v", firstPage, err)
	}
	remaining, err := f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: job, Marker: firstPage.Marker, MaxItems: aws.Int32(10), SortKey: iamtypes.SortKeyTypeServiceNamespaceDescending})
	if err != nil || remaining.IsTruncated || !slices.Equal(organizationNamespaces(remaining), []string{"s3", "kms", "iam"}) {
		t.Fatalf("remaining=%+v err=%v", remaining, err)
	}
	_, err = f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: job, Marker: firstPage.Marker, SortKey: iamtypes.SortKeyTypeServiceNamespaceAscending})
	assertAPIError(t, err, "InvalidInput")
}

func TestOrganizationsAccessReportSelectedPolicyFailureAndIsolation(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	unit := f.unit(t, f.rootID, "reports")
	path := f.rootPath + "/" + unit
	policy := f.policy(t, "Unattached", allow(`["iam:GetUser","s3:GetObject","sqs:SendMessage"]`, "*"), "")
	job := f.generate(t, path, policy)
	out := finishOrganizationReport(t, f.clock, f.iam, job)
	if !slices.Equal(organizationNamespaces(out), []string{"iam", "s3", "sqs"}) || aws.ToInt32(out.NumberOfServicesNotAccessed) != 3 {
		t.Fatalf("unattached policy=%+v", out)
	}
	for _, row := range out.AccessDetails {
		if row.LastAuthenticatedTime != nil || row.EntityPath != nil || aws.ToInt32(row.TotalAuthenticatedEntities) != 0 {
			t.Fatalf("invented account activity=%+v", row)
		}
		if aws.ToString(row.ServiceNamespace) == "iam" {
			if aws.ToString(row.Region) != "us-east-1" {
				t.Fatalf("unused IAM region=%+v", row)
			}
		} else if row.Region != nil {
			t.Fatalf("invented default region=%+v", row)
		}
	}
	for _, test := range []struct {
		key   iamtypes.SortKeyType
		names []string
	}{
		{iamtypes.SortKeyTypeLastAuthenticatedTimeAscending, []string{"s3", "sqs", "iam"}},
		{iamtypes.SortKeyTypeLastAuthenticatedTimeDescending, []string{"iam", "sqs", "s3"}},
	} {
		ordered, err := f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: job, SortKey: test.key})
		if err != nil || !slices.Equal(organizationNamespaces(ordered), test.names) {
			t.Fatalf("AWS unused ordering %s=%+v %v", test.key, ordered, err)
		}
	}
	for _, test := range []struct{ name, path, policy, code string }{
		{"trailing slash", path + "/", "", "INVALID_ORGANIZATIONS_ENTITY_PATH"},
		{"missing OU", f.rootPath + "/ou-abcd-00000000", "", "INVALID_ORGANIZATIONS_ENTITY_PATH"},
		{"missing policy", path, "p-00000000", "INVALID_ORGANIZATIONS_POLICY"},
	} {
		t.Run(test.name, func(t *testing.T) {
			job := f.generate(t, test.path, test.policy)
			failed := finishOrganizationReport(t, f.clock, f.iam, job)
			if failed.JobStatus != iamtypes.JobStatusTypeFailed || failed.ErrorDetails == nil || aws.ToString(failed.ErrorDetails.Code) != test.code || failed.AccessDetails != nil || failed.NumberOfServicesAccessible != nil {
				t.Fatalf("failed job=%+v", failed)
			}
		})
	}
	_, err := f.iam.GenerateOrganizationsAccessReport(t.Context(), &iam.GenerateOrganizationsAccessReportInput{EntityPath: aws.String("o-aaaaaaaaaa/" + f.rootID)})
	assertAPIError(t, err, "AccessDenied")
	member := f.account(t, unit, "member")
	_, err = f.cloud.iam(member, "test", "").GenerateOrganizationsAccessReport(t.Context(), &iam.GenerateOrganizationsAccessReportInput{EntityPath: &path})
	assertAPIError(t, err, "AccessDenied")
	_, key, secret := f.cloud.user(t, "test", "reporter")
	putUserPolicy(t, f.iam, "reporter", allow(`["iam:GenerateOrganizationsAccessReport","iam:GetOrganizationsAccessReport","organizations:Describe*","organizations:List*"]`, "*"))
	reader := f.cloud.iam(key, secret, "")
	generated, err := reader.GenerateOrganizationsAccessReport(t.Context(), &iam.GenerateOrganizationsAccessReportInput{EntityPath: &path, OrganizationsPolicyId: &policy})
	if err != nil {
		t.Fatal(err)
	}
	finishOrganizationReport(t, f.clock, reader, generated.JobId)
	_, err = f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: generated.JobId})
	assertAPIError(t, err, "NoSuchEntity")
	secondKey, err := f.iam.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: aws.String("reporter")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.cloud.iam(aws.ToString(secondKey.AccessKey.AccessKeyId), aws.ToString(secondKey.AccessKey.SecretAccessKey), "").GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: generated.JobId}); err != nil {
		t.Fatal(err)
	}
	_, err = reader.GetServiceLastAccessedDetails(t.Context(), &iam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	// IAM authorization applies before report-type isolation.
	assertAPIError(t, err, "AccessDenied")
	putUserPolicy(t, f.iam, "reporter", allow(`["iam:GetServiceLastAccessedDetails","iam:GetOrganizationsAccessReport"]`, "*"))
	_, err = reader.GetServiceLastAccessedDetails(t.Context(), &iam.GetServiceLastAccessedDetailsInput{JobId: generated.JobId})
	assertAPIError(t, err, "NoSuchEntity")
	if _, err := reader.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: generated.JobId}); err != nil {
		t.Fatal("completed report unexpectedly needs generation dependencies:", err)
	}
}

func TestOrganizationsAccessReportAuthorizationResourceAndPolicyCondition(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	unit := f.unit(t, f.rootID, "reports")
	path := f.rootPath + "/" + unit
	policy := f.policy(t, "Selected", allow(`"sqs:*"`, "*"), "")
	_, key, secret := f.cloud.user(t, "test", "restricted-reporter")
	putUserPolicy(t, f.iam, "restricted-reporter", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"iam:GenerateOrganizationsAccessReport","Resource":%q,"Condition":{"StringEquals":{"iam:OrganizationsPolicyId":%q}}},{"Effect":"Allow","Action":["iam:GetOrganizationsAccessReport","organizations:Describe*","organizations:List*"],"Resource":"*"}]}`, "arn:aws:iam::000000000000:access-report/"+path, policy))
	reader := f.cloud.iam(key, secret, "")
	generated, err := reader.GenerateOrganizationsAccessReport(t.Context(), &iam.GenerateOrganizationsAccessReportInput{EntityPath: &path, OrganizationsPolicyId: &policy})
	if err != nil {
		t.Fatal(err)
	}
	if out := finishOrganizationReport(t, f.clock, reader, generated.JobId); out.JobStatus != iamtypes.JobStatusTypeCompleted {
		t.Fatalf("authorized report=%+v", out)
	}
	_, err = reader.GenerateOrganizationsAccessReport(t.Context(), &iam.GenerateOrganizationsAccessReportInput{EntityPath: &path})
	assertAPIError(t, err, "AccessDenied")
	_, err = reader.GenerateOrganizationsAccessReport(t.Context(), &iam.GenerateOrganizationsAccessReportInput{EntityPath: aws.String(strings.TrimSuffix(path, "/"+unit)), OrganizationsPolicyId: &policy})
	assertAPIError(t, err, "AccessDenied")
}

func TestOrganizationsAccessReportReusesCallerSnapshotAndRefreshes(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) { testOrganizationsAccessReportReusesCallerSnapshotAndRefreshes(t, backend) })
	}
}

func testOrganizationsAccessReportReusesCallerSnapshotAndRefreshes(t *testing.T, backend string) {
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
	}
	f := newOrganizationReportFixture(t, backends)
	unit := f.unit(t, f.rootID, "reports")
	path := f.rootPath + "/" + unit
	policy := f.policy(t, "Reusable", allow(`"s3:GetObject"`, "*"), "")
	input := &iam.GenerateOrganizationsAccessReportInput{EntityPath: &path, OrganizationsPolicyId: &policy}
	// Concurrent requests for the same selection must publish one job. The
	// repository owns lookup and insertion in the accepting transaction.
	var workers sync.WaitGroup
	ids := make(chan string, 8)
	failures := make(chan error, 8)
	for range 8 {
		workers.Go(func() {
			out, err := f.iam.GenerateOrganizationsAccessReport(t.Context(), input)
			if err != nil {
				failures <- err
				return
			}
			ids <- aws.ToString(out.JobId)
		})
	}
	workers.Wait()
	close(ids)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var id string
	for value := range ids {
		if id != "" && value != id {
			t.Fatalf("same selection published multiple jobs: %q %q", id, value)
		}
		id = value
	}
	first := finishOrganizationReport(t, f.clock, f.iam, &id)
	if !slices.Equal(organizationNamespaces(first), []string{"s3"}) {
		t.Fatalf("first report=%+v", first)
	}
	if _, err := f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &policy, Content: aws.String(allow(`"sqs:SendMessage"`, "*"))}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, f.clock, 54*time.Second)
	cached, err := f.iam.GenerateOrganizationsAccessReport(t.Context(), input)
	if err != nil || aws.ToString(cached.JobId) != id {
		t.Fatalf("recent report not reused: %+v %v", cached, err)
	}
	advanceClock(t, f.clock, 6*time.Second)
	refreshed, err := f.iam.GenerateOrganizationsAccessReport(t.Context(), input)
	if err != nil || aws.ToString(refreshed.JobId) == id {
		t.Fatalf("expired report reused: %+v %v", refreshed, err)
	}
	current := finishOrganizationReport(t, f.clock, f.iam, refreshed.JobId)
	if !slices.Equal(organizationNamespaces(current), []string{"sqs"}) {
		t.Fatalf("updated SCP not captured: %+v", current)
	}
	old, err := f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: &id})
	if err != nil || !slices.Equal(organizationNamespaces(old), []string{"s3"}) {
		t.Fatalf("old job mutated: %+v %v", old, err)
	}
}

func TestOrganizationsAccessReportMissingReadPermissionsFailAsynchronously(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	unit := f.unit(t, f.rootID, "reports")
	path := f.rootPath + "/" + unit
	policy := f.policy(t, "Selected", allow(`"sqs:*"`, "*"), "")
	_, key, secret := f.cloud.user(t, "test", "iam-only-reporter")
	putUserPolicy(t, f.iam, "iam-only-reporter", allow(`["iam:GenerateOrganizationsAccessReport","iam:GetOrganizationsAccessReport"]`, "*"))
	reader := f.cloud.iam(key, secret, "")
	input := &iam.GenerateOrganizationsAccessReportInput{EntityPath: &path, OrganizationsPolicyId: &policy}
	accepted, err := reader.GenerateOrganizationsAccessReport(t.Context(), input)
	if err != nil {
		t.Fatal("missing Organizations read permissions rejected acceptance:", err)
	}
	failed := finishOrganizationReport(t, f.clock, reader, accepted.JobId)
	if failed.JobStatus != iamtypes.JobStatusTypeFailed || failed.ErrorDetails == nil || aws.ToString(failed.ErrorDetails.Code) != "ORGANIZATIONS_REPORT_ACCESS_DENIED" || failed.AccessDetails != nil {
		t.Fatalf("missing generation dependency=%+v", failed)
	}
	putUserPolicy(t, f.iam, "iam-only-reporter", allow(`["iam:GenerateOrganizationsAccessReport","iam:GetOrganizationsAccessReport","organizations:Describe*","organizations:List*"]`, "*"))
	cached, err := reader.GenerateOrganizationsAccessReport(t.Context(), input)
	if err != nil || aws.ToString(cached.JobId) != aws.ToString(accepted.JobId) {
		t.Fatalf("failure not reused: %+v %v", cached, err)
	}
	advanceClock(t, f.clock, time.Minute)
	refreshed, err := reader.GenerateOrganizationsAccessReport(t.Context(), input)
	if err != nil || aws.ToString(refreshed.JobId) == aws.ToString(accepted.JobId) {
		t.Fatalf("authorized regeneration=%+v %v", refreshed, err)
	}
	complete := finishOrganizationReport(t, f.clock, reader, refreshed.JobId)
	if complete.JobStatus != iamtypes.JobStatusTypeCompleted || !slices.Equal(organizationNamespaces(complete), []string{"sqs"}) {
		t.Fatalf("new permissions not used: %+v", complete)
	}
}

func TestOrganizationsAccessReportGenerationSlotAndCurrentSCPRequirement(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	unit := f.unit(t, f.rootID, "reports")
	path := f.rootPath + "/" + unit
	firstPolicy := f.policy(t, "First", allow(`"s3:GetObject"`, "*"), "")
	secondPolicy := f.policy(t, "Second", allow(`"sqs:SendMessage"`, "*"), "")
	_, key, secret := f.cloud.user(t, "test", "other-owner")
	putUserPolicy(t, f.iam, "other-owner", allow(`["iam:GenerateOrganizationsAccessReport","iam:GetOrganizationsAccessReport","organizations:Describe*","organizations:List*"]`, "*"))
	other := f.cloud.iam(key, secret, "")
	first := f.generate(t, path, firstPolicy)
	input := &iam.GenerateOrganizationsAccessReportInput{EntityPath: &path, OrganizationsPolicyId: &secondPolicy}
	for _, caller := range []*iam.Client{f.iam, other} {
		_, err := caller.GenerateOrganizationsAccessReport(t.Context(), input)
		assertAPIError(t, err, "ReportGenerationLimitExceeded")
	}
	if cached := f.generate(t, path, firstPolicy); aws.ToString(cached) != aws.ToString(first) {
		t.Fatal("reuse consumed another generation slot")
	}
	finishOrganizationReport(t, f.clock, f.iam, first)
	second, err := other.GenerateOrganizationsAccessReport(t.Context(), input)
	if err != nil {
		t.Fatal("completed job retained generation slot:", err)
	}
	finishOrganizationReport(t, f.clock, other, second.JobId)
	if _, err := f.org.DisablePolicyType(t.Context(), &organizations.DisablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeServiceControlPolicy}); err != nil {
		t.Fatal(err)
	}
	_, err = other.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: second.JobId})
	assertAPIError(t, err, "AccessDenied")
	_, err = f.iam.GenerateOrganizationsAccessReport(t.Context(), &iam.GenerateOrganizationsAccessReportInput{EntityPath: &path, OrganizationsPolicyId: &firstPolicy})
	assertAPIError(t, err, "AccessDenied")
	if _, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeServiceControlPolicy}); err != nil {
		t.Fatal(err)
	}
	if _, err := other.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: second.JobId}); err != nil {
		t.Fatal("reenabled SCPs hid retained report:", err)
	}
}

func TestOrganizationsAccessReportManagementAccountIgnoresPolicy(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	path := f.rootPath + "/000000000000"
	job := f.generate(t, path, "p-missing0")
	out := finishOrganizationReport(t, f.clock, f.iam, job)
	if out.JobStatus != iamtypes.JobStatusTypeCompleted || aws.ToInt32(out.NumberOfServicesAccessible) != int32(len(out.AccessDetails)) {
		t.Fatalf("management report=%+v", out)
	}
	found := false
	for _, row := range out.AccessDetails {
		if aws.ToString(row.ServiceNamespace) == "iam" {
			found = true
			if aws.ToString(row.EntityPath) != path || aws.ToInt32(row.TotalAuthenticatedEntities) != 1 {
				t.Fatalf("management activity=%+v", row)
			}
		}
	}
	if !found {
		t.Fatal("management report omitted IAM")
	}
	page, err := f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: job})
	if err != nil || len(page.AccessDetails) != 100 || !page.IsTruncated || aws.ToInt32(page.NumberOfServicesAccessible) != aws.ToInt32(out.NumberOfServicesAccessible) {
		t.Fatalf("default page=%+v %v", page, err)
	}
}

func TestOrganizationsAccessReportCurrentNativeMetadata(t *testing.T) {
	var fixture struct {
		Observations []struct {
			Case   string
			Input  struct{ SortKey iamtypes.SortKeyType }
			Output iam.GetOrganizationsAccessReportOutput
		}
	}
	awsReadFixture(t, "iam/organizations_access_metadata_20260927.json", &fixture)
	f := newOrganizationReportFixture(t, nil)
	unit := f.unit(t, f.rootID, "metadata")
	job := f.generate(t, f.rootPath+"/"+unit, "")
	finishOrganizationReport(t, f.clock, f.iam, job)
	for _, row := range fixture.Observations {
		if row.Output.JobStatus != iamtypes.JobStatusTypeCompleted {
			continue
		}
		t.Run(row.Case, func(t *testing.T) {
			out, err := f.iam.GetOrganizationsAccessReport(t.Context(), &iam.GetOrganizationsAccessReportInput{JobId: job, MaxItems: new(int32(1000)), SortKey: row.Input.SortKey})
			if err != nil {
				t.Fatal(err)
			}
			if out.IsTruncated != row.Output.IsTruncated || aws.ToInt32(out.NumberOfServicesAccessible) != aws.ToInt32(row.Output.NumberOfServicesAccessible) || aws.ToInt32(out.NumberOfServicesNotAccessed) != aws.ToInt32(row.Output.NumberOfServicesNotAccessed) || !reflect.DeepEqual(out.AccessDetails, row.Output.AccessDetails) {
				t.Fatalf("native empty-OU report mismatch for %s: got %+v, want %+v", row.Input.SortKey, out, row.Output)
			}
		})
	}
}
