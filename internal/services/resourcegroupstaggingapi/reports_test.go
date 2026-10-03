package resourcegroupstaggingapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/resourcegroupstaggingapi"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type complianceOwners struct {
	resources    map[Scope][]Resource
	policies     map[string]string
	organization Organization
	regions      map[string][]string
}

func (o *complianceOwners) List(ctx context.Context, _ string) ([]Resource, error) {
	return o.resources[scopeFor(ctx)], nil
}
func (*complianceOwners) Tag(context.Context, Resource, map[string]string) error {
	return errors.New("unused mutation")
}
func (*complianceOwners) Untag(context.Context, Resource, []string) error {
	return errors.New("unused mutation")
}
func (o *complianceOwners) EffectiveTagPolicy(ctx context.Context) (string, error) {
	return o.policies[scopeFor(ctx).AccountID], nil
}
func (o *complianceOwners) Organization(ctx context.Context) (Organization, error) {
	if scopeFor(ctx).AccountID != o.organization.ManagementAccountID {
		return Organization{}, failure("ConstraintViolationException", "Management account required.")
	}
	return o.organization, nil
}
func (o *complianceOwners) Regions(_ context.Context, id string) ([]string, error) {
	return o.regions[id], nil
}
func (*complianceOwners) RequiredResourceTypes(kind string) ([]string, error) {
	if kind == "ec2:ALL_SUPPORTED" {
		return []string{"ec2:instance", "ec2:volume"}, nil
	}
	return []string{kind}, nil
}
func (*complianceOwners) CloudFormationTypes(kind string) ([]string, error) {
	return map[string][]string{"ec2:instance": {"AWS::EC2::Instance"}, "ec2:volume": {"AWS::EC2::Volume"}, "s3:bucket": {"AWS::S3::Bucket"}}[kind], nil
}

type reportDestination struct {
	objects                    map[string][]byte
	validateErr, errorDelivery error
	duringDelivery             func(context.Context)
}

func (d *reportDestination) ValidateDestination(context.Context, string, string) error {
	return d.validateErr
}
func (d *reportDestination) Deliver(ctx context.Context, bucket, key, _ string, data []byte) error {
	if d.duringDelivery != nil {
		d.duringDelivery(ctx)
	}
	if d.errorDelivery != nil {
		return d.errorDelivery
	}
	d.objects[bucket+"/"+key] = append([]byte(nil), data...)
	return nil
}

func governanceFixture(t *testing.T) (*Service, *complianceOwners, *reportDestination, context.Context) {
	t.Helper()
	owners := &complianceOwners{resources: map[Scope][]Resource{}, policies: map[string]string{}, regions: map[string][]string{}, organization: Organization{ID: "o-exampleorg", ManagementAccountID: "111111111111", Targets: []Target{{ID: "r-root", Type: "ROOT"}, {ID: "ou-root-work", Type: "OU", ParentID: "r-root"}, {ID: "111111111111", Type: "ACCOUNT", ParentID: "r-root"}, {ID: "222222222222", Type: "ACCOUNT", ParentID: "ou-root-work"}, {ID: "333333333333", Type: "ACCOUNT", ParentID: "ou-root-work"}}}}
	for _, id := range []string{"111111111111", "222222222222", "333333333333"} {
		owners.regions[id] = []string{"us-west-2", "us-east-1"}
	}
	source := clock.NewManual(time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC))
	destination := &reportDestination{objects: map[string][]byte{}}
	service := &Service{repository: NewMemoryRepository(nil), resources: owners, policies: owners, governance: owners, reports: destination, clock: source, authorizer: authorization.NewWithClock(nil, nil, source)}
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	return service, owners, destination, ctx
}
func summaryFor(t *testing.T, s *Service, ctx context.Context, in *api.GetComplianceSummaryInput) *api.GetComplianceSummaryOutput {
	t.Helper()
	var out *api.GetComplianceSummaryOutput
	if err := s.repository.Update(ctx, func(tx Transaction) error { var err error; out, err = s.getComplianceSummary(tx, in); return err }); err != nil {
		t.Fatal(err)
	}
	return out
}
func describeFor(t *testing.T, s *Service, ctx context.Context) *api.DescribeReportCreationOutput {
	t.Helper()
	var out *api.DescribeReportCreationOutput
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		out, err = s.describeReportCreation(tx, &api.DescribeReportCreationInput{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != want {
		t.Fatalf("error = %v; want %s", err, want)
	}
}

func TestComplianceSummaryFiltersGroupingAndPagination(t *testing.T) {
	s, owners, _, ctx := governanceFixture(t)
	owners.policies["222222222222"] = `{"tags":{"env":{"tag_key":"Env","tag_value":["prod"],"report_required_tag_for":["ec2:instance"]}}}`
	owners.policies["333333333333"] = `{"tags":{"env":{"tag_key":"Env","tag_value":["dev"]}}}`
	east := Scope{"aws", "222222222222", "us-east-1"}
	west := Scope{"aws", "222222222222", "us-west-2"}
	other := Scope{"aws", "333333333333", "us-east-1"}
	owners.resources[east] = []Resource{{ARN: "arn:aws:ec2:us-east-1:222222222222:instance/i-bad", ResourceType: "ec2:instance", Tags: map[string]string{"Env": "dev"}}, {ARN: "arn:aws:ec2:us-east-1:222222222222:instance/i-good", ResourceType: "ec2:instance", Tags: map[string]string{"Env": "prod", "Owner": "team"}}, {ARN: "arn:aws:ec2:us-east-1:222222222222:instance/i-never", ResourceType: "ec2:instance"}, {ARN: "arn:aws:ec2:us-east-1:222222222222:instance/i-previous", ResourceType: "ec2:instance"}}
	owners.resources[west] = []Resource{{ARN: "arn:aws:ec2:us-west-2:222222222222:volume/vol-bad", ResourceType: "ec2:volume", Tags: map[string]string{"env": "dev"}}}
	owners.resources[other] = []Resource{{ARN: "arn:aws:ec2:us-east-1:333333333333:instance/i-other", ResourceType: "ec2:instance", Tags: map[string]string{"Env": "dev"}}}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutMembership(Membership{Scope: east, Service: "ec2", ARN: owners.resources[east][3].ARN})
	}); err != nil {
		t.Fatal(err)
	}
	in := &api.GetComplianceSummaryInput{TargetIdFilters: api.TargetIdFilterList{"ou-root-work"}, GroupBy: api.GroupBy{api.GroupByAttributeREGION, api.GroupByAttributeRESOURCE_TYPE}, MaxResults: new(api.MaxResultsGetComplianceSummary(1))}
	first := summaryFor(t, s, ctx, in)
	if len(first.SummaryList) != 1 || value(first.SummaryList[0].Region) != "us-east-1" || *first.SummaryList[0].NonCompliantResources != 2 || value(first.PaginationToken) == "" {
		t.Fatalf("first page: %+v", first)
	}
	in.PaginationToken = first.PaginationToken
	second := summaryFor(t, s, ctx, in)
	if len(second.SummaryList) != 1 || value(second.SummaryList[0].Region) != "us-west-2" || *second.SummaryList[0].NonCompliantResources != 1 || second.PaginationToken != nil {
		t.Fatalf("second page: %+v", second)
	}
	filtered := summaryFor(t, s, ctx, &api.GetComplianceSummaryInput{TargetIdFilters: api.TargetIdFilterList{"r-root"}, RegionFilters: api.RegionFilterList{"us-east-1"}, ResourceTypeFilters: api.ResourceTypeFilterList{"ec2:instance"}, TagKeyFilters: api.TagKeyFilterList{"Env", "Owner"}})
	if len(filtered.SummaryList) != 1 || *filtered.SummaryList[0].NonCompliantResources != 1 {
		t.Fatalf("AND across dimensions / OR inside tag keys: %+v", filtered)
	}
	grouped := summaryFor(t, s, ctx, &api.GetComplianceSummaryInput{TargetIdFilters: api.TargetIdFilterList{"ou-root-work"}, GroupBy: api.GroupBy{api.GroupByAttributeTARGET_ID}})
	if len(grouped.SummaryList) != 1 || value(grouped.SummaryList[0].TargetId) != "ou-root-work" || value(grouped.SummaryList[0].TargetIdType) != "OU" || *grouped.SummaryList[0].NonCompliantResources != 3 {
		t.Fatalf("OU aggregation: %+v", grouped)
	}
	empty := summaryFor(t, s, ctx, &api.GetComplianceSummaryInput{RegionFilters: api.RegionFilterList{"eu-north-1"}})
	if len(empty.SummaryList) != 0 {
		t.Fatalf("fabricated empty-region rows: %+v", empty)
	}
}

func TestComplianceGlobalInventoryCountedOnce(t *testing.T) {
	s, owners, _, ctx := governanceFixture(t)
	owners.policies["222222222222"] = `{"tags":{"env":{"tag_key":"Env","tag_value":["prod"]}}}`
	global := Resource{ARN: "arn:aws:cloudwatch::222222222222:dashboard/example", ResourceType: "cloudwatch:dashboard", Tags: map[string]string{"Env": "dev"}}
	for _, region := range owners.regions["222222222222"] {
		owners.resources[Scope{"aws", "222222222222", region}] = []Resource{global}
	}
	out := summaryFor(t, s, ctx, &api.GetComplianceSummaryInput{GroupBy: api.GroupBy{api.GroupByAttributeREGION}})
	if len(out.SummaryList) != 1 || *out.SummaryList[0].NonCompliantResources != 1 || value(out.SummaryList[0].Region) != "us-east-1" {
		t.Fatalf("global duplication: %+v", out)
	}
}

func TestRequiredTagsMemberPolicyAndWildcardPagination(t *testing.T) {
	s, owners, _, ctx := governanceFixture(t)
	metadata := awsctx.FromContext(ctx)
	metadata.AccountID = "222222222222"
	metadata.Region = "us-west-2"
	metadata.PrincipalARN = "arn:aws:iam::222222222222:root"
	metadata.PrincipalID = metadata.AccountID
	ctx = awsctx.WithMetadata(ctx, metadata)
	owners.policies[metadata.AccountID] = `{"tags":{"owner":{"tag_key":"Owner","report_required_tag_for":["ec2:ALL_SUPPORTED","ec2:instance"]},"env":{"tag_key":"Env","report_required_tag_for":["ec2:instance"]}}}`
	call := func(in *api.ListRequiredTagsInput) *api.ListRequiredTagsOutput {
		var out *api.ListRequiredTagsOutput
		t.Helper()
		if err := s.repository.Update(ctx, func(tx Transaction) error { var err error; out, err = s.listRequiredTags(tx, in); return err }); err != nil {
			t.Fatal(err)
		}
		return out
	}
	first := call(&api.ListRequiredTagsInput{MaxResults: new(api.MaxResultsForListRequiredTags(1))})
	want := api.RequiredTag{ResourceType: new(api.ResourceType("ec2:instance")), ReportingTagKeys: api.ReportingTagKeys{"Env", "Owner"}, CloudFormationResourceTypes: api.CloudFormationResourceTypes{"AWS::EC2::Instance"}}
	if len(first.RequiredTags) != 1 || !reflect.DeepEqual(first.RequiredTags[0], want) || first.NextToken == nil {
		t.Fatalf("required tags: %+v", first)
	}
	second := call(&api.ListRequiredTagsInput{MaxResults: new(api.MaxResultsForListRequiredTags(1)), NextToken: first.NextToken})
	if len(second.RequiredTags) != 1 || value(second.RequiredTags[0].ResourceType) != "ec2:volume" || !reflect.DeepEqual(second.RequiredTags[0].ReportingTagKeys, api.ReportingTagKeys{"Owner"}) || second.NextToken != nil {
		t.Fatalf("next required tags: %+v", second)
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.listRequiredTags(tx, &api.ListRequiredTagsInput{MaxResults: new(api.MaxResultsForListRequiredTags(2)), NextToken: first.NextToken})
		return err
	})
	requireCode(t, err, "InvalidParameterException")
}

func TestReportDeliveryStateAndRetainedFailure(t *testing.T) {
	s, owners, destination, ctx := governanceFixture(t)
	accountScope := Scope{"aws", "222222222222", "us-west-2"}
	owners.policies[accountScope.AccountID] = `{"tags":{"env":{"tag_key":"Env","tag_value":["prod"]}}}`
	owners.resources[accountScope] = []Resource{{ARN: "arn:aws:ec2:us-west-2:222222222222:instance/i-report", ResourceType: "ec2:instance", Tags: map[string]string{"env": "dev"}}}
	if got := value(describeFor(t, s, ctx).Status); got != "NO REPORT" {
		t.Fatal(got)
	}
	input := &api.StartReportCreationInput{S3Bucket: new(api.S3Bucket("reports-bucket"))}
	if _, err := s.startReportCreation(ctx, input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.startReportCreation(ctx, input); err == nil {
		t.Fatal("concurrent report accepted")
	} else {
		requireCode(t, err, "ConcurrentModificationException")
	}
	if got := value(describeFor(t, s, ctx).Status); got != "RUNNING" {
		t.Fatal(got)
	}
	job, found, err := (reportJobs{s}).Next(ctx)
	if err != nil || !found {
		t.Fatalf("pending report: %v %v", found, err)
	}
	if err := (reportJobs{s}).Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	report := describeFor(t, s, ctx)
	if value(report.Status) != "SUCCEEDED" || value(report.StartDate) != "2026-04-05T06:07:08Z" || value(report.S3Location) != "s3://reports-bucket/AwsTagPolicies/o-exampleorg/2026-04-05T06:07:08Z/report.csv" {
		t.Fatalf("completed report: %+v", report)
	}
	data := destination.objects[strings.TrimPrefix(value(report.S3Location), "s3://")]
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"AccountId", "Region", "ResourceType", "ComplianceStatus", "NoncompliantKeys", "KeysWithNoncompliantValues", "ResourceARN"}, {"222222222222", "us-west-2", "ec2:instance", "FALSE", "env", "env", owners.resources[accountScope][0].ARN}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("CSV = %#v; want %#v", rows, want)
	}
	// A new service instance consumes the retained latest state and a post-admit
	// authority failure becomes FAILED, never a fabricated successful export.
	reopened := *s
	destination.errorDelivery = failure("AccessDenied", "Destination policy now denies the caller.")
	if _, err := reopened.startReportCreation(ctx, input); err != nil {
		t.Fatal(err)
	}
	job, _, err = (reportJobs{&reopened}).Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := (reportJobs{&reopened}).Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	failed := describeFor(t, &reopened, ctx)
	if value(failed.Status) != "FAILED" || value(failed.ErrorMessage) != "AccessDenied: Destination policy now denies the caller." || failed.S3Location != nil {
		t.Fatalf("failed report: %+v", failed)
	}
	destination.validateErr = invalid("The destination bucket must be in us-east-1.")
	if _, err := reopened.startReportCreation(ctx, input); err == nil {
		t.Fatal("invalid destination admitted")
	}
	if got := value(describeFor(t, &reopened, ctx).Status); got != "FAILED" {
		t.Fatal("rejected request replaced retained failure:", got)
	}
}

func TestReportLeaseRecoveryAndStaleCompletion(t *testing.T) {
	s, _, destination, ctx := governanceFixture(t)
	input := &api.StartReportCreationInput{S3Bucket: new(api.S3Bucket("reports-bucket"))}
	if _, err := s.startReportCreation(ctx, input); err != nil {
		t.Fatal(err)
	}
	job, _, err := (reportJobs{s}).Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	destination.duringDelivery = func(context.Context) { cancel() }
	if err := (reportJobs{s}).Run(cancelled, job); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got := value(describeFor(t, s, ctx).Status); got != "RUNNING" {
		t.Fatal(got)
	}
	recovered := *s
	destination.duringDelivery = nil
	if err := s.clock.(*clock.Manual).Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	next, _, err := (reportJobs{&recovered}).Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if next.Version == job.Version {
		t.Fatal("lease did not fence stale worker")
	}
	if err := (reportJobs{&recovered}).Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if got := value(describeFor(t, s, ctx).Status); got != "RUNNING" {
		t.Fatal("stale job completed:", got)
	}
	// Supersede the selected incarnation while its external effect is in flight.
	destination.duringDelivery = func(context.Context) {
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			report, _, err := tx.Report(scopeFor(ctx))
			if err != nil {
				return err
			}
			report.Version++
			report.ErrorMessage = "replacement"
			return tx.PutReport(report)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := (reportJobs{&recovered}).Run(ctx, next); err != nil {
		t.Fatal(err)
	}
	if got := describeFor(t, s, ctx); value(got.Status) != "RUNNING" || value(got.ErrorMessage) != "replacement" {
		t.Fatalf("stale completion replaced intent: %+v", got)
	}
	destination.duringDelivery = nil
	if err := s.clock.(*clock.Manual).Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	next, _, err = (reportJobs{&recovered}).Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := (reportJobs{&recovered}).Run(ctx, next); err != nil {
		t.Fatal(err)
	}
	if got := value(describeFor(t, s, ctx).Status); got != "SUCCEEDED" {
		t.Fatal(got)
	}
}

func TestGovernanceIAMScopeAndCallerIsolation(t *testing.T) {
	s, _, _, ctx := governanceFixture(t)
	metadata := awsctx.FromContext(ctx)
	metadata.PrincipalARN = "arn:aws:iam::111111111111:user/unprivileged"
	metadata.PrincipalID = "unprivileged"
	denied := awsctx.WithMetadata(ctx, metadata)
	err := s.repository.Update(denied, func(tx Transaction) error {
		_, err := s.getComplianceSummary(tx, &api.GetComplianceSummaryInput{})
		return err
	})
	var wire *awswire.Error
	if !errors.As(err, &wire) || !strings.Contains(wire.Code, "AccessDenied") {
		t.Fatalf("IAM denial: %v", err)
	}
	metadata = awsctx.FromContext(ctx)
	metadata.Region = "us-west-2"
	if _, err := s.startReportCreation(awsctx.WithMetadata(ctx, metadata), &api.StartReportCreationInput{S3Bucket: new(api.S3Bucket("reports-bucket"))}); err == nil {
		t.Fatal("wrong region admitted")
	} else {
		requireCode(t, err, "InvalidParameterException")
	}
	metadata = awsctx.FromContext(ctx)
	metadata.AccountID = "222222222222"
	metadata.PrincipalID = metadata.AccountID
	metadata.PrincipalARN = "arn:aws:iam::222222222222:root"
	if _, err := s.startReportCreation(awsctx.WithMetadata(ctx, metadata), &api.StartReportCreationInput{S3Bucket: new(api.S3Bucket("reports-bucket"))}); err == nil {
		t.Fatal("member report admitted")
	} else {
		requireCode(t, err, "ConstraintViolationException")
	}
	metadata = awsctx.FromContext(ctx)
	metadata.SessionPolicies = []string{`{"Statement":[]}`}
	metadata.SessionTags = map[string]string{"Team": "alpha"}
	report := Report{Scope: scopeFor(ctx), Version: 1, Status: "RUNNING", StartedAt: s.clock.Now(), Due: s.clock.Now(), Caller: metadata}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutReport(report) }); err != nil {
		t.Fatal(err)
	}
	metadata.SessionTags["Team"] = "changed"
	if err := s.repository.View(ctx, func(reader Reader) error {
		stored, _, err := reader.Report(report.Scope)
		if err != nil {
			return err
		}
		encoded, _ := json.Marshal(stored.Caller)
		if stored.Caller.SessionTags["Team"] != "alpha" {
			t.Fatalf("caller authority aliased: %s", encoded)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
