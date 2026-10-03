package stackd_test

import (
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

func (c cloudClients) account(key, secret, token string) *account.Client {
	return account.New(account.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func enableAccountRegion(t *testing.T, c cloudClients, source *clock.Manual, key, region string) {
	t.Helper()
	if _, err := c.account(key, "test", "").EnableRegion(t.Context(), &account.EnableRegionInput{RegionName: &region}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 2*time.Minute)
}

func TestAccountRegionLifecycleEnforcesSTSAndPreservesResources(t *testing.T) {
	source := clock.NewManual(time.Now().UTC())
	c := clockCloud(t, stackd.Config{Clock: source})
	ctx, region, target := t.Context(), "af-south-1", "111111111111"
	enableAccountRegion(t, c, source, "test", region)
	admin := c.account(target, "test", "")
	role, err := c.iam(target, "test", "").CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("region-boundary"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	assume := func(want string) {
		t.Helper()
		out, err := c.sts("test", "test", "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("region-test")}, func(o *sts.Options) { o.Region = region })
		if want != "" {
			assertAPIError(t, err, want)
			if out != nil {
				t.Fatal("denial returned credentials")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		tokenWorksInRegion(t, c, out.Credentials, region, true)
	}
	status := func(want accounttypes.RegionOptStatus) {
		t.Helper()
		out, err := admin.GetRegionOptStatus(ctx, &account.GetRegionOptStatusInput{RegionName: &region})
		if err != nil || out.RegionOptStatus != want {
			t.Fatalf("status want %s: %+v %v", want, out, err)
		}
	}
	session, err := c.sts(target, "test", "").GetSessionToken(ctx, &sts.GetSessionTokenInput{})
	if err != nil {
		t.Fatal(err)
	}
	status(accounttypes.RegionOptStatusDisabled)
	assume("AccessDenied")
	tokenWorksInRegion(t, c, session.Credentials, region, false)
	if _, err := admin.EnableRegion(ctx, &account.EnableRegionInput{RegionName: &region}); err != nil {
		t.Fatal(err)
	}
	status(accounttypes.RegionOptStatusEnabling)
	_, err = admin.EnableRegion(ctx, &account.EnableRegionInput{RegionName: &region})
	assertAPIError(t, err, "ConflictException")
	_, err = admin.DisableRegion(ctx, &account.DisableRegionInput{RegionName: &region})
	assertAPIError(t, err, "ConflictException")
	assume("AccessDenied")
	advanceClock(t, source, 2*time.Minute-time.Nanosecond)
	status(accounttypes.RegionOptStatusEnabling)
	advanceClock(t, source, time.Nanosecond)
	status(accounttypes.RegionOptStatusEnabled)
	assume("")
	tokenWorksInRegion(t, c, session.Credentials, region, true)
	queueClient := sqs.New(c.sessionSQS(session.Credentials).Options(), func(o *sqs.Options) { o.Region = region })
	queue, err := queueClient.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("survives-region-disable")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.EnableRegion(ctx, &account.EnableRegionInput{RegionName: &region})
	var invalid *accounttypes.ValidationException
	if !errors.As(err, &invalid) || invalid.Reason != accounttypes.ValidationExceptionReasonInvalidRegionOptTarget {
		t.Fatalf("modeled validation: %v", err)
	}
	if _, err := admin.DisableRegion(ctx, &account.DisableRegionInput{RegionName: &region}); err != nil {
		t.Fatal(err)
	}
	status(accounttypes.RegionOptStatusDisabling)
	assume("")
	tokenWorksInRegion(t, c, session.Credentials, region, true)
	advanceClock(t, source, time.Minute)
	status(accounttypes.RegionOptStatusDisabled)
	assume("AccessDenied")
	tokenWorksInRegion(t, c, session.Credentials, region, false)
	_, err = queueClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl})
	assertAPIError(t, err, "InvalidClientTokenId")
	enableAccountRegion(t, c, source, target, region)
	if _, err := queueClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl}); err != nil {
		t.Fatal("region disable deleted resource state", err)
	}
}

func TestAccountRegionPermissionsPaginationAndValidation(t *testing.T) {
	c := newCloudClients(t)
	ctx := t.Context()
	root := c.account("test", "test", "")
	_, key, secret := c.user(t, "test", "account-reader")
	reader := c.account(key, secret, "")
	in := &account.GetRegionOptStatusInput{RegionName: aws.String("us-east-1")}
	_, err := reader.GetRegionOptStatus(ctx, in)
	assertAPIError(t, err, "AccessDeniedException")
	putUserPolicy(t, c.iam("test", "test", ""), "account-reader", `{"Statement":{"Effect":"Allow","Action":"account:GetRegionOptStatus","Resource":"arn:aws:account::000000000000:account","Condition":{"StringEquals":{"account:TargetRegion":"us-east-1"}}}}`)
	if _, err := reader.GetRegionOptStatus(ctx, in); err != nil {
		t.Fatal(err)
	}
	_, err = reader.GetRegionOptStatus(ctx, &account.GetRegionOptStatusInput{RegionName: aws.String("eu-west-1")})
	assertAPIError(t, err, "AccessDeniedException")
	for _, region := range []string{"unknown-region", "cn-north-1"} {
		_, err = root.GetRegionOptStatus(ctx, &account.GetRegionOptStatusInput{RegionName: &region})
		var invalid *accounttypes.ValidationException
		if !errors.As(err, &invalid) || invalid.Reason != accounttypes.ValidationExceptionReasonFieldValidationFailed || len(invalid.FieldList) != 1 || aws.ToString(invalid.FieldList[0].Name) != "RegionName" {
			t.Fatalf("validation details: %v", err)
		}
	}
	_, err = root.GetRegionOptStatus(ctx, &account.GetRegionOptStatusInput{RegionName: aws.String("US-EAST-1")})
	assertAPIError(t, err, "AccessDeniedException")
	_, err = root.DisableRegion(ctx, &account.DisableRegionInput{RegionName: aws.String("us-east-1")})
	assertAPIError(t, err, "ValidationException")
	page, err := root.ListRegions(ctx, &account.ListRegionsInput{MaxResults: aws.Int32(1)})
	if err != nil || len(page.Regions) != 1 || aws.ToString(page.Regions[0].RegionName) != "af-south-1" || page.NextToken == nil {
		t.Fatalf("first page: %+v %v", page, err)
	}
	next, err := root.ListRegions(ctx, &account.ListRegionsInput{MaxResults: aws.Int32(1), NextToken: page.NextToken})
	if err != nil || len(next.Regions) != 1 || aws.ToString(next.Regions[0].RegionName) != "ap-east-1" {
		t.Fatalf("next page: %+v %v", next, err)
	}
	_, err = c.account("111111111111", "test", "").ListRegions(ctx, &account.ListRegionsInput{NextToken: page.NextToken})
	assertAPIError(t, err, "ValidationException")
	_, err = root.ListRegions(ctx, &account.ListRegionsInput{NextToken: page.NextToken, RegionOptStatusContains: []accounttypes.RegionOptStatus{accounttypes.RegionOptStatusEnabled}})
	assertAPIError(t, err, "ValidationException")
	all := account.NewListRegionsPaginator(root, &account.ListRegionsInput{MaxResults: aws.Int32(2)})
	previous, count := "", 0
	for all.HasMorePages() {
		page, err := all.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Regions {
			name := aws.ToString(row.RegionName)
			if name <= previous {
				t.Fatal("unstable pagination", name, previous)
			}
			previous = name
			count++
		}
	}
	if count < 30 {
		t.Fatal("incomplete catalogue", count)
	}
	_, err = root.GetGovCloudAccountInformation(ctx, &account.GetGovCloudAccountInformationInput{})
	assertAPIError(t, err, "UnknownOperationException")
}
