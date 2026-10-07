package integrations

import (
	"context"
	"errors"
	"fmt"
	"stackd/internal/awswire"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/cloudformation"
)

type cfnACfgRecoveryKey struct{}

func cfnACfgOwnerContext(ctx context.Context, r cloudformation.ResourceRequest, kind string, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	recover, _ := ctx.Value(cfnACfgRecoveryKey{}).(bool)
	return appconfig.WithCloudFormationTarget(ctx, appconfig.CloudFormationOwnership{Owner: cfnMessagingOwner(r), Token: cfnMessagingHash(r.Token)}, kind, create, recover)
}
func cfnACfgRecoveryMissing(ctx context.Context) error {
	recover, _ := ctx.Value(cfnACfgRecoveryKey{}).(bool)
	if recover {
		return &awswire.Error{Code: "ResourceNotFoundException", Message: "This resource incarnation has no admitted native resource.", StatusCode: 404}
	}
	return nil
}

// Only an exact private-row observation certifies no admission. Missing
// dependencies or failed follow-up reads leave creation recovery uncertain.
func cfnACfgRecoveryObservation(result cloudformation.ResourceResult, err error) (cloudformation.ResourceResult, error) {
	if err == nil {
		return result, nil
	}
	var wire *awswire.Error
	if errors.As(err, &wire) && cfnACfgMissing(err) && wire.Message != "This resource incarnation has no admitted native resource." {
		return result, fmt.Errorf("AppConfig creation recovery dependencies are unavailable: %v", err)
	}
	return result, err
}

// Tags are customer configuration only. Native private row claims carry authority.
func cfnAppCustomerTags(r cloudformation.ResourceRequest) map[string]string {
	tags, _ := cfnComputeTags(r.Properties)
	for key, value := range r.Tags {
		if _, overridden := tags[key]; !overridden {
			tags[key] = value
		}
	}
	return tags
}

func (h cfnACfgApplication) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}

func (h cfnACfgEnvironment) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}

func (h cfnACfgProfile) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}

func (h cfnACfgStrategy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}

func (h cfnACfgHosted) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}

func (h cfnACfgDeployment) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}

func (h cfnACfgExtension) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}

func (h cfnACfgAssociation) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}

func (h cfnACfgExperiment) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}

func (h cfnACfgExperimentRun) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnACfgRecoveryObservation(h.Create(context.WithValue(ctx, cfnACfgRecoveryKey{}, true), r))
}
