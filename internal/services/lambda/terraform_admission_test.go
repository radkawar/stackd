package lambda

import (
	"strings"
	"testing"

	api "stackd/internal/awsapi/lambda"
)

func TestTerraformDisabledSnapStartAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		config *api.SnapStart
		code   string
	}{
		{"omitted", nil, ""},
		{"disabled", &api.SnapStart{ApplyOn: new(api.SnapStartApplyOn("None"))}, ""},
		{"enabled", &api.SnapStart{ApplyOn: new(api.SnapStartApplyOn("PublishedVersions"))}, "NotImplementedException"},
		{"invalid", &api.SnapStart{ApplyOn: new(api.SnapStartApplyOn("invalid"))}, "InvalidParameterValueException"},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := validateSnapStart(test.config)
			if test.code == "" {
				if wire != nil {
					t.Fatal(wire)
				}
			} else if wire == nil || wire.Code != test.code {
				t.Fatalf("admission = %v, want %s", wire, test.code)
			}
		})
	}
}

func TestTerraformClearUnimplementedAttachmentsReachesOrdinaryDeployment(t *testing.T) {
	repository := NewMemoryRepository(nil)
	ctx, ref := aliasOwnerFixture(t, repository)
	service := aliasOwnerService(t, Config{Repository: repository})
	// There is deliberately no executor: clearing absent EFS and disabling
	// snapshots must reach ordinary deployment admission, not claim completion.
	_, wire := service.updateConfiguration(ctx, &api.UpdateFunctionConfigurationInput{
		FunctionName:      new(api.FunctionName(ref.Name)),
		FileSystemConfigs: api.FileSystemConfigList{},
		SnapStart:         &api.SnapStart{ApplyOn: new(api.SnapStartApplyOn("None"))},
	})
	if wire == nil || !strings.Contains(wire.Message, "No Lambda container executor") {
		t.Fatalf("ordinary executor boundary = %v", wire)
	}
	_, wire = service.updateConfiguration(ctx, &api.UpdateFunctionConfigurationInput{
		FunctionName: new(api.FunctionName(ref.Name)),
		SnapStart:    &api.SnapStart{ApplyOn: new(api.SnapStartApplyOn("PublishedVersions"))},
	})
	if wire == nil || !strings.Contains(wire.Message, "snapshot execution") {
		t.Fatalf("enabled snapshot boundary = %v", wire)
	}
}
