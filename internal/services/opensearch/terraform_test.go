package opensearch_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	modern "github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/opensearch/types"
)

// This shared-domain HTTP harness proves SDK control serialization only; native
// options, document persistence and authentication belong to the engine fixture.
func TestTerraformDisabledOptionSDKUpdate(t *testing.T) {
	_, client, _ := legacyClients(t)
	updated, err := client.UpdateDomainConfig(t.Context(), &modern.UpdateDomainConfigInput{
		DomainName:            aws.String(legacyTestName),
		CognitoOptions:        &types.CognitoOptions{Enabled: aws.Bool(false)},
		SoftwareUpdateOptions: &types.SoftwareUpdateOptions{AutoSoftwareUpdateEnabled: aws.Bool(false)},
		DomainEndpointOptions: &types.DomainEndpointOptions{EnforceHTTPS: aws.Bool(false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := updated.DomainConfig
	if config.CognitoOptions == nil || config.CognitoOptions.Options == nil || config.CognitoOptions.Options.Enabled == nil || *config.CognitoOptions.Options.Enabled {
		t.Fatalf("disabled Cognito state missing or enabled: %#v", config.CognitoOptions)
	}
	if config.SoftwareUpdateOptions == nil || config.SoftwareUpdateOptions.Options == nil || config.SoftwareUpdateOptions.Options.AutoSoftwareUpdateEnabled == nil || *config.SoftwareUpdateOptions.Options.AutoSoftwareUpdateEnabled {
		t.Fatalf("disabled software update state missing or enabled: %#v", config.SoftwareUpdateOptions)
	}
	if config.CognitoOptions.Status.UpdateVersion != 2 || config.SoftwareUpdateOptions.Status.UpdateVersion != 2 {
		t.Fatal("disabled options did not use the authoritative domain config version")
	}
	described, err := client.DescribeDomain(t.Context(), &modern.DescribeDomainInput{DomainName: aws.String(legacyTestName)})
	if err != nil {
		t.Fatal(err)
	}
	status := described.DomainStatus
	if status.CognitoOptions == nil || status.CognitoOptions.Enabled == nil || *status.CognitoOptions.Enabled || status.SoftwareUpdateOptions == nil || status.SoftwareUpdateOptions.AutoSoftwareUpdateEnabled == nil || *status.SoftwareUpdateOptions.AutoSoftwareUpdateEnabled {
		t.Fatalf("disabled options were not returned through DescribeDomain: %#v", status)
	}
}
