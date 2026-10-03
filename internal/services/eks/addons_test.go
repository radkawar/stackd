package eks_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/smithy-go"
	"stackd/internal/awscatalog"
	"stackd/internal/services/eks"
)

func TestAddonCatalogUsesCapturedAWSReleases(t *testing.T) {
	client, _, _ := sdkFixture(t)
	data, err := os.ReadFile("../../../testdata/aws/eks/addons_coredns_native_versions.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Output sdk.DescribeAddonVersionsOutput
	}
	if err = json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	actual, err := client.DescribeAddonVersions(t.Context(), &sdk.DescribeAddonVersionsInput{AddonName: aws.String("coredns"), KubernetesVersion: aws.String("1.33")})
	if err != nil {
		t.Fatal(err)
	}
	var want, got []string
	for _, addon := range capture.Output.Addons {
		for _, version := range addon.AddonVersions {
			want = append(want, aws.ToString(version.AddonVersion))
		}
	}
	for _, addon := range actual.Addons {
		for _, version := range addon.AddonVersions {
			got = append(got, aws.ToString(version.AddonVersion))
			configuration, err := client.DescribeAddonConfiguration(t.Context(), &sdk.DescribeAddonConfigurationInput{AddonName: addon.AddonName, AddonVersion: version.AddonVersion})
			if err != nil || aws.ToString(configuration.AddonVersion) != aws.ToString(version.AddonVersion) {
				t.Fatalf("advertised AWS release cannot be configured: %+v %v", configuration, err)
			}
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog releases = %v; captured mapped releases = %v", got, want)
	}
	for _, upstream := range []string{"v1.12.1", "v1.12.3"} {
		if _, err = client.DescribeAddonConfiguration(t.Context(), &sdk.DescribeAddonConfigurationInput{AddonName: aws.String("coredns"), AddonVersion: aws.String(upstream)}); err == nil {
			t.Fatalf("accepted upstream image version as AWS release: %s", upstream)
		}
	}
}

func TestAddonUpdateParamsSurviveCompletionAndTokenReplay(t *testing.T) {
	client, repository, _ := sdkFixture(t)
	key := eks.Key{Scope: eks.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "addon-params"}
	if err := repository.Update(t.Context(), func(tx eks.Transaction) error {
		if err := tx.PutCluster(eks.Cluster{Key: key, ID: "cluster-id", Status: "ACTIVE", KubernetesVersion: "1.33"}); err != nil {
			return err
		}
		return tx.PutAddon(eks.Addon{Key: key, ID: "addon-id", Name: "coredns", Status: "ACTIVE", Version: "v1.12.1-eksbuild.2", Created: time.Unix(1, 0)})
	}); err != nil {
		t.Fatal(err)
	}
	input := &sdk.UpdateAddonInput{ClusterName: aws.String(key.Name), AddonName: aws.String("coredns"), AddonVersion: aws.String("v1.12.3-eksbuild.1"), ConfigurationValues: aws.String(`{"replicaCount":2}`), ResolveConflicts: types.ResolveConflicts("PRESERVE"), ClientRequestToken: aws.String("stable-addon-update")}
	accepted, err := client.UpdateAddon(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	params := func(update *types.Update) map[string]string {
		result := map[string]string{}
		for _, param := range update.Params {
			result[string(param.Type)] = aws.ToString(param.Value)
		}
		return result
	}
	want := map[string]string{"AddonVersion": "v1.12.3-eksbuild.1", "ConfigurationValues": `{"replicaCount":2}`, "ResolveConflicts": "PRESERVE"}
	if !reflect.DeepEqual(params(accepted.Update), want) {
		t.Fatalf("accepted parameters = %v", params(accepted.Update))
	}
	if err = repository.Update(t.Context(), func(tx eks.Transaction) error {
		update, err := tx.ClusterUpdate(key, aws.ToString(accepted.Update.Id))
		if err != nil {
			return err
		}
		update.Status = "Failed"
		if err = tx.PutClusterUpdate(update); err != nil {
			return err
		}
		addon, err := tx.Addon(key, "coredns")
		if err != nil {
			return err
		}
		addon.Status, addon.Operation, addon.Version, addon.Configuration = "UPDATE_FAILED", "", "v1.12.1-eksbuild.2", `{"replicaCount":1}`
		return tx.PutAddon(addon)
	}); err != nil {
		t.Fatal(err)
	}
	replay, err := client.UpdateAddon(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	described, err := client.DescribeUpdate(t.Context(), &sdk.DescribeUpdateInput{Name: aws.String(key.Name), AddonName: input.AddonName, UpdateId: accepted.Update.Id})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(replay.Update.Id) != aws.ToString(accepted.Update.Id) || string(replay.Update.Status) != "Failed" || !reflect.DeepEqual(params(replay.Update), want) || !reflect.DeepEqual(params(described.Update), want) {
		t.Fatalf("accepted update identity or parameters changed after completion: replay=%+v described=%+v", replay.Update, described.Update)
	}
	input.ConfigurationValues = aws.String(`{"replicaCount":3}`)
	if _, err = client.UpdateAddon(t.Context(), input); err == nil {
		t.Fatal("token replay admitted different configuration")
	}
}

func TestDeleteAddonBusyStateUsesModeledErrorWithoutMutation(t *testing.T) {
	model, _ := awscatalog.LookupService("eks")
	operation, _ := model.Operation("DeleteAddon")
	for _, state := range []struct{ cluster, addon string }{{"ACTIVE", "CREATING"}, {"ACTIVE", "UPDATING"}, {"UPDATING", "ACTIVE"}} {
		t.Run(state.cluster+"-"+state.addon, func(t *testing.T) {
			client, repository, _ := sdkFixture(t)
			key := eks.Key{Scope: eks.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "delete-addon"}
			before := eks.Addon{Key: key, ID: "addon-id", Name: "coredns", Status: state.addon, Version: "v1.12.3-eksbuild.1"}
			if err := repository.Update(t.Context(), func(tx eks.Transaction) error {
				if err := tx.PutCluster(eks.Cluster{Key: key, ID: "cluster-id", Status: state.cluster}); err != nil {
					return err
				}
				return tx.PutAddon(before)
			}); err != nil {
				t.Fatal(err)
			}
			_, err := client.DeleteAddon(t.Context(), &sdk.DeleteAddonInput{ClusterName: aws.String(key.Name), AddonName: aws.String(before.Name)})
			var apiError smithy.APIError
			if !errors.As(err, &apiError) || !slices.Contains(operation.Errors, awscatalog.ShapeID("com.amazonaws.eks#"+apiError.ErrorCode())) {
				t.Fatalf("busy deletion returned an unmodeled error: %v", err)
			}
			if err = repository.View(t.Context(), func(tx eks.Reader) error {
				after, err := tx.Addon(key, before.Name)
				if err == nil && !reflect.DeepEqual(after, before) {
					t.Fatalf("rejected deletion changed the addon: %+v", after)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
