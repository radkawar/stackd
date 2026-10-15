package opensearch

import (
	"encoding/json"
	"testing"

	api "stackd/internal/awsapi/opensearch"
)

// These are control admission tests, not native-engine execution evidence.
// Provider 6.68.0 expands disabled blocks and empty computed endpoint enums.
func TestTerraformDisabledControlAdmission(t *testing.T) {
	cases := []struct {
		name     string
		fields   string
		accepted bool
	}{
		{"omitted controls", `{}`, true},
		{"disabled provider blocks", `{"ClusterConfig":{"InstanceCount":1,"DedicatedMasterEnabled":false,"ZoneAwarenessEnabled":false,"WarmEnabled":false,"MultiAZWithStandbyEnabled":false},"EBSOptions":{"EBSEnabled":false},"AdvancedSecurityOptions":{"Enabled":false},"EncryptionAtRestOptions":{"Enabled":false},"NodeToNodeEncryptionOptions":{"Enabled":false},"DomainEndpointOptions":{"EnforceHTTPS":false,"CustomEndpointEnabled":false,"TLSSecurityPolicy":""},"CognitoOptions":{"Enabled":false},"SoftwareUpdateOptions":{"AutoSoftwareUpdateEnabled":false}}`, true},
		{"named TLS policy", `{"DomainEndpointOptions":{"EnforceHTTPS":false,"TLSSecurityPolicy":"Policy-Min-TLS-1-2-2019-07"}}`, false},
		{"managed HTTPS", `{"DomainEndpointOptions":{"EnforceHTTPS":true}}`, false},
		{"custom endpoint", `{"DomainEndpointOptions":{"CustomEndpointEnabled":false,"CustomEndpoint":"search.example.com"}}`, false},
		{"Cognito enabled", `{"CognitoOptions":{"Enabled":true}}`, false},
		{"Cognito dependency despite disabled", `{"CognitoOptions":{"Enabled":false,"UserPoolId":"pool"}}`, false},
		{"automatic update enabled", `{"SoftwareUpdateOptions":{"AutoSoftwareUpdateEnabled":true}}`, false},
		{"blue-green software setting", `{"SoftwareUpdateOptions":{"AutoSoftwareUpdateEnabled":false,"UseLatestServiceSoftwareForBlueGreen":false}}`, false},
		{"capacity class", `{"ClusterConfig":{"InstanceCount":1,"InstanceType":"m3.medium.search"}}`, false},
		{"EBS capacity despite disabled", `{"EBSOptions":{"EBSEnabled":false,"VolumeSize":10}}`, false},
		{"KMS despite disabled", `{"EncryptionAtRestOptions":{"Enabled":false,"KmsKeyId":"key"}}`, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var create api.CreateDomainRequest
			if err := json.Unmarshal([]byte(test.fields), &create); err != nil {
				t.Fatal(err)
			}
			create.DomainName = new(api.DomainName("provider-disabled"))
			create.EngineVersion = new(api.VersionString(EngineVersion))
			if err := validateCreate(&create); (err == nil) != test.accepted {
				t.Fatalf("create accepted=%t: %v", test.accepted, err)
			}
			var update api.UpdateDomainConfigRequest
			if err := json.Unmarshal([]byte(test.fields), &update); err != nil {
				t.Fatal(err)
			}
			update.DomainName = create.DomainName
			if err := validateUpdate(&update); (err == nil) != test.accepted {
				t.Fatalf("update accepted=%t: %v", test.accepted, err)
			}
		})
	}
}
