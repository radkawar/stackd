package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	buildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"

	"stackd"
	"stackd/clock"
	buildruntime "stackd/compute/codebuild"
	"stackd/compute/docker"
	"stackd/internal/awstest"
)

func fleetTaggingClient(c cloudClients, region, key, secret string) *codebuild.Client {
	return codebuild.New(codebuild.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func fleetTagMap(tags []buildtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return out
}

// Replays free signed native controls; no AWS fleet or reserved capacity was
// created for this fixture.
func TestResourceGroupsTaggingCodeBuildFleetControls(t *testing.T) {
	var fixture struct {
		Account, Region string
		Observations    []struct {
			Case, Operation, Code string
			Input, Output         json.RawMessage
		}
	}
	awsReadFixture(t, "resourcegroupstaggingapi/codebuild_fleets.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account})
			client := fleetTaggingClient(c, fixture.Region, "test", "test")
			for _, row := range fixture.Observations {
				t.Run(row.Case, func(t *testing.T) {
					options := client.Options()
					options.APIOptions = append(options.APIOptions, awstest.JSONBody(row.Input))
					output, err := awstest.CallSDK(t.Context(), codebuild.New(options), row.Operation, row.Input)
					if row.Code != "Success" {
						assertAPIError(t, err, row.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					out := output.(*codebuild.BatchGetFleetsOutput)
					var expected codebuild.BatchGetFleetsOutput
					if err := json.Unmarshal(row.Output, &expected); err != nil {
						t.Fatal(err)
					}
					if len(out.Fleets) != len(expected.Fleets) || !reflect.DeepEqual(out.FleetsNotFound, expected.FleetsNotFound) {
						t.Fatalf("missing fleet read: got %+v want %+v", out, expected)
					}
				})
			}
		})
	}
}

// This scenario uses the real native reservation owner, not seeded fleet rows or
// an executor mock. It reserves one local idle container and never creates paid
// AWS reserved capacity. Use the same pinned image control as compute/codebuild.
func TestResourceGroupsTaggingCodeBuildFleetNativeOwners(t *testing.T) {
	image := os.Getenv("STACKD_CODEBUILD_FLEET_TEST_IMAGE")
	if image == "" {
		t.Skip("set STACKD_CODEBUILD_FLEET_TEST_IMAGE to a pinned preinstalled Linux amd64 image with /bin/sh and sleep")
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("STACKD_CODEBUILD_FLEET_TEST_DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			executor, err := buildruntime.NewDockerExecutor(engine, buildruntime.DockerConfig{Namespace: fmt.Sprintf("fleet-tags-%s-%d", backend, time.Now().UnixNano()), FleetImage: image})
			if err != nil {
				t.Fatal(err)
			}
			var arn string
			// Registered before retainedCloud so workers stop before native cleanup.
			t.Cleanup(func() {
				if arn == "" {
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := executor.ReleaseFleet(ctx, arn); err != nil {
					t.Errorf("release owned fleet: %v", err)
				}
			})
			source := clock.NewManual(time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source, CodeBuildExecutor: executor, CodeBuildFleetImage: image}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				server := httptest.NewUnstartedServer(nil)
				config.PublicEndpoint = "http://" + server.Listener.Addr().String()
				config.ComputeEndpoint = config.PublicEndpoint
				cloud, err := stackd.New(config)
				if err != nil {
					server.Close()
					t.Fatal(err)
				}
				server.Config.Handler = cloud
				server.Start()
				return cloud, server
			})
			native := fleetTaggingClient(c, "us-east-1", "test", "test")
			created, err := native.CreateFleet(t.Context(), &codebuild.CreateFleetInput{Name: aws.String("tagged-reservation"), BaseCapacity: aws.Int32(1), ComputeType: buildtypes.ComputeTypeBuildGeneral1Small, EnvironmentType: buildtypes.EnvironmentTypeLinuxContainer, OverflowBehavior: buildtypes.FleetOverflowBehaviorOnDemand, Tags: []buildtypes.Tag{{Key: aws.String("source"), Value: aws.String("native")}, {Key: aws.String("empty")}}})
			if err != nil {
				t.Fatal(err)
			}
			arn = aws.ToString(created.Fleet.Arn)
			readFleet := func() buildtypes.Fleet {
				t.Helper()
				out, err := native.BatchGetFleets(t.Context(), &codebuild.BatchGetFleetsInput{Names: []string{arn}})
				if err != nil || len(out.Fleets) != 1 {
					t.Fatalf("native fleet read: %+v, %v", out, err)
				}
				return out.Fleets[0]
			}
			initial := readFleet()
			deadline := time.Now().Add(30 * time.Second)
			for initial.Status == nil || initial.Status.StatusCode != buildtypes.FleetStatusCodeActive {
				if time.Now().After(deadline) {
					t.Fatalf("fleet never acquired real capacity: %+v", initial.Status)
				}
				time.Sleep(25 * time.Millisecond)
				initial = readFleet()
			}
			capacity, err := executor.InspectFleet(t.Context(), arn)
			if err != nil || capacity.State != "ACTIVE" || capacity.Capacity != 1 || capacity.Ready != 1 || capacity.InUse != 0 {
				t.Fatalf("native reserved capacity: %+v, %v", capacity, err)
			}
			assertFleet := func(want map[string]string) {
				t.Helper()
				got := readFleet()
				if !reflect.DeepEqual(fleetTagMap(got.Tags), want) {
					t.Fatalf("native tags got %v want %v", fleetTagMap(got.Tags), want)
				}
				got.Tags, initial.Tags = nil, nil
				got.LastModified, initial.LastModified = nil, nil
				if !reflect.DeepEqual(got, initial) {
					t.Fatalf("tags-only mutation changed fleet configuration: got %+v want %+v", got, initial)
				}
			}
			tags := taggingClient(c, "us-east-1", "test", "test")
			assertInventory := func(want map[string]string) {
				t.Helper()
				out, err := tags.GetResources(t.Context(), &resourcegroupstaggingapi.GetResourcesInput{ResourceTypeFilters: []string{"codebuild:fleet"}})
				if err != nil {
					t.Fatal(err)
				}
				if got := taggingMappings(out.ResourceTagMappingList); !reflect.DeepEqual(got, map[string]map[string]string{arn: want}) {
					t.Fatalf("fleet inventory got %v want %v", got, want)
				}
			}
			assertInventory(map[string]string{"source": "native", "empty": ""})
			_, key, secret := c.user(t, "test", "fleet-tagger")
			putUserPolicy(t, c.iam("test", "test", ""), "fleet-tagger", `{"Statement":{"Effect":"Allow","Action":"tag:*","Resource":"*"}}`)
			caller := taggingClient(c, "us-east-1", key, secret)
			request := &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{arn}, Tags: map[string]string{"caller": "allowed"}}
			denied, err := caller.TagResources(t.Context(), request)
			if err != nil || len(denied.FailedResourcesMap) != 1 || !strings.Contains(string(denied.FailedResourcesMap[arn].ErrorCode), "AccessDenied") {
				t.Fatalf("dependent native authority: %+v, %v", denied, err)
			}
			assertFleet(map[string]string{"source": "native", "empty": ""})
			policy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"tag:*","Resource":"*"},{"Effect":"Allow","Action":"codebuild:UpdateFleet","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/source":"native","aws:RequestTag/caller":"allowed"},"ForAllValues:StringEquals":{"aws:TagKeys":["source","empty","caller"]}}}]}`, arn)
			putUserPolicy(t, c.iam("test", "test", ""), "fleet-tagger", policy)
			limited := fleetTaggingClient(c, "us-east-1", key, secret)
			_, err = limited.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &arn, Tags: []buildtypes.Tag{{Key: aws.String("caller"), Value: aws.String("forbidden")}}})
			assertAPIError(t, err, "AccessDeniedException")
			source.Advance(time.Minute)
			allowed, err := caller.TagResources(t.Context(), request)
			if err != nil || len(allowed.FailedResourcesMap) != 0 {
				t.Fatalf("condition-authorized fleet mutation: %+v, %v", allowed, err)
			}
			assertFleet(map[string]string{"source": "native", "empty": "", "caller": "allowed"})
			removed, err := caller.UntagResources(t.Context(), &resourcegroupstaggingapi.UntagResourcesInput{ResourceARNList: []string{arn}, TagKeys: []string{"empty"}})
			if err != nil || len(removed.FailedResourcesMap) != 0 {
				t.Fatalf("native fleet untag: %+v, %v", removed, err)
			}
			assertFleet(map[string]string{"source": "native", "caller": "allowed"})
			nativeTags := []buildtypes.Tag{{Key: aws.String("source"), Value: aws.String("native")}, {Key: aws.String("native-edit"), Value: aws.String("visible")}}
			updated, err := native.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &arn, Tags: nativeTags})
			if err != nil || updated.Fleet == nil || updated.Fleet.LastModified == nil || !updated.Fleet.LastModified.Equal(source.Now()) {
				t.Fatalf("native tag replacement: %+v, %v", updated, err)
			}
			want := map[string]string{"source": "native", "native-edit": "visible"}
			assertFleet(want)
			assertInventory(want)

			for _, input := range []codebuild.UpdateFleetInput{
				{BaseCapacity: aws.Int32(2)},
				{ComputeType: buildtypes.ComputeTypeBuildGeneral1Medium},
				{EnvironmentType: buildtypes.EnvironmentTypeArmContainer},
				{FleetServiceRole: aws.String("arn:aws:iam::000000000000:role/other")},
				{ImageId: aws.String("ami-0123456789abcdef0")},
				{ComputeConfiguration: &buildtypes.ComputeConfiguration{}},
				{ProxyConfiguration: &buildtypes.ProxyConfiguration{}},
				{ScalingConfiguration: &buildtypes.ScalingConfigurationInput{}},
				{VpcConfig: &buildtypes.VpcConfig{}},
				{OverflowBehavior: buildtypes.FleetOverflowBehavior("INVALID")},
			} {
				input.Arn, input.Tags = &arn, []buildtypes.Tag{{Key: aws.String("inert"), Value: aws.String("must-not-commit")}}
				_, err := native.UpdateFleet(t.Context(), &input)
				assertAPIError(t, err, "InvalidInputException")
				assertFleet(want)
			}
			for _, invalid := range [][]buildtypes.Tag{
				{{Key: aws.String("")}},
				{{Key: aws.String("aws:reserved")}},
				{{Key: aws.String(strings.Repeat("k", 128))}},
				{{Key: aws.String("key"), Value: aws.String(strings.Repeat("v", 256))}},
				{{Key: aws.String("bad!key")}},
				{{Key: aws.String("duplicate")}, {Key: aws.String("duplicate")}},
			} {
				_, err := native.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &arn, Tags: invalid})
				assertAPIError(t, err, "InvalidInputException")
				assertFleet(want)
			}
			full := append([]buildtypes.Tag{}, nativeTags...)
			for i := len(full); i < 50; i++ {
				full = append(full, buildtypes.Tag{Key: aws.String(fmt.Sprintf("key-%d", i)), Value: aws.String("value")})
			}
			if _, err := native.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &arn, Tags: full}); err != nil {
				t.Fatal(err)
			}
			overLimit, err := tags.TagResources(t.Context(), &resourcegroupstaggingapi.TagResourcesInput{ResourceARNList: []string{arn}, Tags: map[string]string{"fifty-first": "rejected"}})
			if err != nil || len(overLimit.FailedResourcesMap) != 1 || string(overLimit.FailedResourcesMap[arn].ErrorCode) != "InvalidInputException" {
				t.Fatalf("merged owner tag limit: %+v, %v", overLimit, err)
			}
			assertFleet(fleetTagMap(full))
			for _, isolated := range []*codebuild.Client{fleetTaggingClient(c, "us-west-2", "test", "test"), fleetTaggingClient(c, "us-east-1", "222222222222", "test")} {
				_, err := isolated.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &arn, Tags: nativeTags})
				assertAPIError(t, err, "ResourceNotFoundException")
			}
			stale := strings.TrimSuffix(arn, aws.ToString(created.Fleet.Id)) + "00000000-0000-4000-8000-000000000000"
			_, err = native.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &stale, Tags: nativeTags})
			assertAPIError(t, err, "ResourceNotFoundException")
			if _, err := native.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &arn, Tags: nativeTags}); err != nil {
				t.Fatal(err)
			}
			putUserPolicy(t, c.iam("test", "test", ""), "fleet-tagger", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"codebuild:UpdateFleet","Resource":"*"}]}`)
			c = reopen()
			native = fleetTaggingClient(c, "us-east-1", "test", "test")
			tags = taggingClient(c, "us-east-1", "test", "test")
			caller = taggingClient(c, "us-east-1", key, secret)
			limited = fleetTaggingClient(c, "us-east-1", key, secret)
			assertFleet(want)
			assertInventory(want)
			denied, err = caller.TagResources(t.Context(), request)
			if err != nil || len(denied.FailedResourcesMap) != 1 || !strings.Contains(string(denied.FailedResourcesMap[arn].ErrorCode), "AccessDenied") {
				t.Fatalf("current native deny after reopen: %+v, %v", denied, err)
			}
			_, err = limited.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &arn, Tags: []buildtypes.Tag{}})
			assertAPIError(t, err, "AccessDeniedException")
			trail := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			event := auditLookupRecord(t, trail, nativeAuditRequestID(t, nil, err), "UpdateFleet")
			if event["errorCode"] != "AccessDeniedException" {
				t.Fatalf("native rejected update audit: %+v", event)
			}
			committed := auditLookupRecord(t, trail, nativeAuditRequestID(t, updated, nil), "UpdateFleet")
			if committed["errorCode"] != nil {
				t.Fatalf("native committed update recorded as rejected: %+v", committed)
			}
			assertFleet(want)
			assertInventory(want)
			// Overflow has a real consumer in the build claim owner. Unlike
			// resizing, this change needs no host replacement/drain transition.
			if _, err := native.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &arn, BaseCapacity: aws.Int32(1), ComputeType: buildtypes.ComputeTypeBuildGeneral1Small, EnvironmentType: buildtypes.EnvironmentTypeLinuxContainer, OverflowBehavior: buildtypes.FleetOverflowBehaviorQueue}); err != nil {
				t.Fatal(err)
			}
			initial.OverflowBehavior = buildtypes.FleetOverflowBehaviorQueue
			assertFleet(want) // An omitted tag list preserves tags.
			// The SDK's explicit empty list must clear tags, not mean omitted tags.
			if _, err := native.UpdateFleet(t.Context(), &codebuild.UpdateFleetInput{Arn: &arn, Tags: []buildtypes.Tag{}}); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			native = fleetTaggingClient(c, "us-east-1", "test", "test")
			tags = taggingClient(c, "us-east-1", "test", "test")
			assertFleet(map[string]string{})
			assertInventory(map[string]string{})
		})
	}
}
