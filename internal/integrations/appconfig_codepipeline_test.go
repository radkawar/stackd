package integrations

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	pipelineapi "stackd/internal/awsapi/codepipeline"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/codepipeline"
	"stackd/internal/services/iam"
	"stackd/internal/services/s3"
)

func TestAppConfigPipelineArtifactUsesRegionalCurrentAuthority(t *testing.T) {
	cases := []struct {
		region, capture, forwarder string
	}{
		{region: "us-east-1", capture: "appconfig_called_via_exact_chain_native.json"},
		{region: "eu-west-1", capture: "appconfig_called_via_exact_eu_west_1_native.json"},
		{region: "us-west-2", capture: "appconfig_called_via_exact_us_west_2_ready_native.json"},
		{region: "us-west-1"},
	}
	for i := range cases {
		if cases[i].capture == "" {
			continue
		}
		body, err := os.ReadFile("../../testdata/aws/codepipeline/" + cases[i].capture)
		if err != nil {
			t.Fatal(err)
		}
		var native struct {
			Region    string
			Condition struct {
				StringEquals map[string]string
			} `json:"consumer_artifact_condition"`
		}
		if err := json.Unmarshal(body, &native); err != nil {
			t.Fatal(err)
		}
		cases[i].forwarder = native.Condition.StringEquals["aws:CalledViaLast"]
		if native.Region != cases[i].region || cases[i].forwarder == "" {
			t.Fatalf("native capture lacks the regional forwarding identity: %s", cases[i].capture)
		}
	}
	for _, tc := range cases {
		t.Run(tc.region, func(t *testing.T) {
			f := newLambdaRoleFixture(t)
			scope := appconfig.Scope{Partition: "aws", AccountID: f.scope.AccountID, Region: tc.region}
			metadata := awsctx.FromContext(f.ctx)
			metadata.Region = tc.region
			caller := awsctx.WithMetadata(t.Context(), metadata)
			root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::" + scope.AccountID + ":root"})
			objects := s3.New(s3.Config{Clock: f.clock, Authorizer: f.adapter.Authorizer})
			defer objects.Close()
			bucket := &s3api.CreateBucketInput{Bucket: new(s3api.BucketName("configuration-artifacts"))}
			if tc.region != "us-east-1" {
				bucket.CreateBucketConfiguration = &s3api.CreateBucketConfiguration{LocationConstraint: new(s3api.BucketLocationConstraint(tc.region))}
			}
			if _, err := appConfigCommand(root, objects, "s3", "CreateBucket", bucket); err != nil {
				t.Fatal(err)
			}
			content := []byte(`{"release":"regional-artifact"}`)
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			member, err := writer.Create("config.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := member.Write(content); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := appConfigCommand(root, objects, "s3", "PutObject", &s3api.PutObjectInput{Bucket: bucket.Bucket, Key: new(s3api.ObjectKey("artifact.zip")), Body: archive.Bytes()}); err != nil {
				t.Fatal(err)
			}
			repository := codepipeline.NewMemoryRepository(nil)
			pipelineScope := codepipeline.Scope{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}
			definition := codepipeline.Definition{Scope: pipelineScope, Incarnation: "original", Declaration: pipelineapi.PipelineDeclaration{
				Version:       new(pipelineapi.PipelineVersion(1)),
				ArtifactStore: &pipelineapi.ArtifactStore{Type: new(pipelineapi.ArtifactStoreType("S3")), Location: new(pipelineapi.ArtifactStoreLocation("configuration-artifacts"))},
				Stages:        pipelineapi.PipelineStageDeclarationList{{Actions: pipelineapi.StageActionDeclarationList{{ActionTypeId: &pipelineapi.ActionTypeId{Provider: new(pipelineapi.ActionProvider("AppConfig"))}}}}},
			}}
			execution := codepipeline.Execution{Scope: pipelineScope, PipelineName: "release", Incarnation: "original", ID: "execution", Version: 1, Status: "Succeeded", Actions: []codepipeline.ActionExecution{{
				ID: "deployment-action", Status: "Succeeded",
				InputArtifacts:        []codepipeline.Artifact{{Name: "Configuration", Bucket: "configuration-artifacts", Key: "artifact.zip"}},
				ResolvedConfiguration: pipelineapi.ActionConfigurationMap{"InputArtifactConfigurationPath": "config.json"},
			}}}
			if err := repository.Update(root, func(tx codepipeline.Transaction) error {
				if err := tx.PutDefinition(definition); err != nil {
					return err
				}
				return tx.PutExecution(execution)
			}); err != nil {
				t.Fatal(err)
			}
			effects := AppConfigEffects{PipelineArtifacts: CodePipelineArtifacts{Repository: repository}, Objects: objects}
			profile := appconfig.Profile{Scope: scope, LocationURI: "codepipeline://release"}
			grant := func(via string) {
				t.Helper()
				f.user.IdentityPolicies.Inline = map[string]string{"artifact": fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::configuration-artifacts/*","Condition":{"StringEquals":{"aws:CalledViaFirst":%q,"aws:CalledViaLast":%q},"ForAllValues:StringEquals":{"aws:CalledVia":[%q]},"Null":{"aws:CalledVia":"false"},"Bool":{"aws:ViaAWSService":"true"}}}}`, via, via, via)}
				f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
			}
			if tc.forwarder == "" {
				grant(cases[0].forwarder)
				_, err := effects.Retrieve(caller, profile, "deployment-action")
				var wire *awswire.Error
				if !errors.As(err, &wire) || wire.Code != "NotImplementedException" || wire.StatusCode != 501 {
					t.Fatalf("uncalibrated region borrowed a forwarding identity: %v", err)
				}
				return
			}
			identities := []string{tc.forwarder}
			for _, other := range cases {
				if other.forwarder != "" && other.region != tc.region {
					identities = append(identities, other.forwarder)
				}
			}
			identities = append(identities, "appconfig.amazonaws.com", tc.forwarder)
			for _, via := range identities {
				grant(via)
				if _, wire := objects.GetObject(caller, &s3api.GetObjectInput{Bucket: bucket.Bucket, Key: new(s3api.ObjectKey("artifact.zip"))}); wire == nil || wire.Code != "AccessDenied" {
					t.Fatalf("forwarded-only policy permitted direct S3 read: %v", wire)
				}
				got, err := effects.Retrieve(caller, profile, "deployment-action")
				if via == tc.forwarder {
					if err != nil || !bytes.Equal(got.Content, content) || got.Version != "deployment-action" {
						t.Fatalf("authorized artifact content: %+v, %v", got, err)
					}
				} else {
					var wire *awswire.Error
					if !errors.As(err, &wire) || wire.Code != "BadRequestException" {
						t.Fatalf("artifact read reused earlier permission: %v", err)
					}
				}
			}
		})
	}
}
