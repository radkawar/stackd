package appconfig_test

import (
	"testing"

	api "stackd/internal/awsapi/appconfig"
	service "stackd/internal/services/appconfig"
)

// A recovered CloudFormation create must observe its own immutable version,
// even after restart, and deletion must refuse another incarnation's version.
func TestCloudFormationHostedVersionOwnership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			h := newControlHarness(t, backend)
			app := h.app("cfn")
			profile := string(*h.profile(&api.CreateConfigurationProfileInput{ApplicationId: new(api.Name(app)), Name: new(api.LongName("hosted")), LocationUri: new(api.Uri("hosted"))}).Id)
			owned := func() *api.CreateHostedConfigurationVersionInput {
				return &api.CreateHostedConfigurationVersionInput{ApplicationId: new(api.Name(app)), ConfigurationProfileId: new(api.LongName(profile)), Content: api.Blob(`{"a":1}`), ContentType: new(api.StringWithLengthBetween1And255("application/json")), LatestVersionNumber: new(api.Integer(0))}
			}
			create := func(token string) *api.HostedConfigurationVersion {
				t.Helper()
				ctx := service.WithCloudFormationOwnership(h.ctx, service.CloudFormationOwnership{Owner: "stack/logical", Token: token})
				out, err := h.command(ctx, "CreateHostedConfigurationVersion", owned())
				if err != nil {
					t.Fatalf("create %s: %v", token, err)
				}
				return out.(*api.HostedConfigurationVersion)
			}
			versions := func() int {
				t.Helper()
				return len(h.call("ListHostedConfigurationVersions", &api.ListHostedConfigurationVersionsInput{ApplicationId: new(api.Name(app)), ConfigurationProfileId: new(api.LongName(profile))}).(*api.HostedConfigurationVersions).Items)
			}
			first := create("one")
			h.restart()
			// The replay succeeds although LatestVersionNumber 0 is now stale.
			if replay := create("one"); *replay.VersionNumber != *first.VersionNumber || versions() != 1 {
				t.Fatalf("recovered create published another version: %d versions, replay %d", versions(), *replay.VersionNumber)
			}
			deleteAs := func(token string) bool {
				ctx := service.WithCloudFormationOwnership(h.ctx, service.CloudFormationOwnership{Owner: "stack/logical", Token: token})
				_, err := h.command(ctx, "DeleteHostedConfigurationVersion", &api.DeleteHostedConfigurationVersionInput{ApplicationId: new(api.Name(app)), ConfigurationProfileId: new(api.LongName(profile)), VersionNumber: first.VersionNumber})
				return err == nil
			}
			if deleteAs("two") {
				t.Fatal("another incarnation deleted the owned version")
			}
			if !deleteAs("one") {
				t.Fatal("the owning incarnation could not delete its version")
			}
			// The cleared binding never resurrects the deleted version.
			in := owned()
			in.LatestVersionNumber = nil
			ctx := service.WithCloudFormationOwnership(h.ctx, service.CloudFormationOwnership{Owner: "stack/logical", Token: "one"})
			out, err := h.command(ctx, "CreateHostedConfigurationVersion", in)
			if err != nil || *out.(*api.HostedConfigurationVersion).VersionNumber == *first.VersionNumber {
				t.Fatalf("recreated version reused a deleted number: %v %v", out, err)
			}
			incomplete := service.WithCloudFormationOwnership(h.ctx, service.CloudFormationOwnership{Owner: "stack/logical"})
			if _, err := h.command(incomplete, "CreateHostedConfigurationVersion", in); err == nil {
				t.Fatal("incomplete ownership identity was accepted")
			}
		})
	}
}
