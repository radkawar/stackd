package integrations

import (
	"strings"
	"testing"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/services/cloudformation"
)

func TestCloudFormationSecretSourceNativeVersionAndStageRules(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSecretFixture(t, backend)
			firstID, secondID := strings.Repeat("a", 32), strings.Repeat("b", 32)
			created, err := cfnComputeCall[api.CreateSecretOutput](f.ctx, f.commands, "secretsmanager", "CreateSecret", map[string]any{"Name": "dynamic-source", "SecretString": "first-version", "ClientRequestToken": firstID})
			if err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(f.ctx, f.commands, "secretsmanager", "PutSecretValue", map[string]any{"SecretId": "dynamic-source", "SecretString": "second-version", "ClientRequestToken": secondID}); err != nil {
				t.Fatal(err)
			}
			f.reopen()
			source := CloudFormationSecretSource{Commands: f.commands}
			for _, tc := range []struct {
				selector       cloudformation.SecretVersionSelector
				value, version string
			}{
				{cloudformation.SecretVersionSelector{SecretID: "dynamic-source"}, "second-version", secondID},
				{cloudformation.SecretVersionSelector{SecretID: cfnComputeValue(created.ARN), VersionStage: "AWSPREVIOUS"}, "first-version", firstID},
				{cloudformation.SecretVersionSelector{SecretID: "dynamic-source", VersionID: firstID}, "first-version", firstID},
			} {
				value, version, err := source.ResolveSecretVersion(f.ctx, tc.selector)
				if err != nil || value != tc.value || version != tc.version {
					t.Fatalf("native selection %#v: %q %q %v", tc.selector, value, version, err)
				}
			}
			if err := cfnComputeRun(f.ctx, f.commands, "secretsmanager", "CreateSecret", map[string]any{"Name": "dynamic-binary", "SecretBinary": "bmV2ZXItbGVhay1iaW5hcnk="}); err != nil {
				t.Fatal(err)
			}
			value, version, err := source.ResolveSecretVersion(f.ctx, cloudformation.SecretVersionSelector{SecretID: "dynamic-binary"})
			if err == nil || value != "" || version != "" || strings.Contains(err.Error(), "never-leak-binary") {
				t.Fatal("binary secret was silently coerced or exposed", err)
			}
		})
	}
}
