package stackd_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func TestAccountRegionEligibilityUsesCredentialAuthorityState(t *testing.T) {
	source := clock.NewManual(time.Now().UTC())
	backends := storage.NewMemory()
	repository := &signedAuthorityRepository{Repository: backends.IAM}
	backends.IAM = repository
	c := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
	enableAccountRegion(t, c, source, "test", "af-south-1")
	_, key, secret := c.user(t, "test", "region-authority")
	plan := &signedAuthorityPlan{key: key, before: func(ctx context.Context) error {
		if _, err := c.account("test", "test", "").DisableRegion(ctx, &account.DisableRegionInput{RegionName: aws.String("af-south-1")}); err != nil {
			return err
		}
		return source.Advance(time.Minute)
	}}
	repository.arm(plan)
	ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
	defer cancel()
	out, err := c.sts(key, secret, "").GetSessionToken(ctx, &sts.GetSessionTokenInput{}, func(o *sts.Options) { o.Region = "af-south-1" })
	plan.wait(t, ctx)
	if plan.hookErr != nil {
		t.Fatal(plan.hookErr)
	}
	assertAPIError(t, err, "AccessDenied")
	if out != nil || len(plan.issued) != 0 {
		t.Fatal("issued credentials after region eligibility changed")
	}
}

func TestAccountPendingRegionTransitionSurvivesReconstruction(t *testing.T) {
	source := clock.NewManual(time.Now().UTC())
	config := stackd.Config{Clock: source, Storage: storage.NewMemory()}
	open := func() (*stackd.Stack, cloudClients) {
		t.Helper()
		handler, err := stackd.New(config)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		t.Cleanup(func() {
			if err := handler.Close(); err != nil {
				t.Error(err)
			}
		})
		return handler, cloudClients{server}
	}
	handler, c := open()
	if _, err := c.account("test", "test", "").EnableRegion(t.Context(), &account.EnableRegionInput{RegionName: aws.String("af-south-1")}); err != nil {
		t.Fatal(err)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	c.server.Close()
	advanceClock(t, source, time.Minute)
	_, c = open()
	check := func(want accounttypes.RegionOptStatus) {
		t.Helper()
		out, err := c.account("test", "test", "").GetRegionOptStatus(t.Context(), &account.GetRegionOptStatusInput{RegionName: aws.String("af-south-1")})
		if err != nil || out.RegionOptStatus != want {
			t.Fatalf("retained region: %+v %v", out, err)
		}
	}
	check(accounttypes.RegionOptStatusEnabling)
	advanceClock(t, source, time.Minute)
	check(accounttypes.RegionOptStatusEnabled)
}
