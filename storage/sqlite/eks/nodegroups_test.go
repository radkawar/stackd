package eks_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/awscatalog"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	domain "stackd/internal/services/eks"
)

func TestNodegroupNativeAbsentParentContracts(t *testing.T) {
	var fixture struct {
		Account string
		Calls   []struct {
			Region, Operation, Error string
			Input                    json.RawMessage
		}
	}
	data, err := os.ReadFile("../../../testdata/aws/eks/nodegroups_absent.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	model, _ := awscatalog.LookupService("eks")
	codes := regexp.MustCompile(`\((\w+Exception)\)`)
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			stores := openRepositories(t, kind)
			service := domain.New(domain.Config{Repository: stores.repo})
			t.Cleanup(func() { _ = service.Close() })
			for _, row := range fixture.Calls {
				operation := ""
				for _, part := range strings.Split(row.Operation, "-") {
					operation += strings.ToUpper(part[:1]) + part[1:]
				}
				input, err := awscommands.NewInput("eks", operation)
				if err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(row.Input, input); err != nil {
					t.Fatal(err)
				}
				expected := codes.FindStringSubmatch(row.Error)
				if len(expected) != 2 {
					t.Fatalf("native capture lacks an AWS error code: %s", row.Error)
				}
				ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: fixture.Account, Region: row.Region, PrincipalARN: "arn:aws:iam::" + fixture.Account + ":root", PrincipalID: fixture.Account})
				op, _ := model.Operation(operation)
				_, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
				if rejected == nil || rejected.Code != expected[1] {
					t.Fatalf("%s/%s: %v; native code %s", row.Region, operation, rejected, expected[1])
				}
			}
		})
	}
}

func TestNodegroupConfigValidationAndDeleteSurviveRestart(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			stores := openRepositories(t, kind)
			key := domain.NodegroupKey{Cluster: clusterKey(), Name: "workers"}
			cluster := domain.Cluster{Key: key.Cluster, ID: "control-incarnation", Status: "ACTIVE", KubernetesVersion: "1.33"}
			group := domain.Nodegroup{Key: key, ID: "group-incarnation", ClusterID: cluster.ID, Status: "ACTIVE", Version: "1.33", Subnets: []string{"subnet-a"}, Labels: map[string]string{"kept": "original"}, Tags: map[string]string{}, MinSize: 0, MaxSize: 2, DesiredSize: 1, Generation: 4, TemplateGeneration: 2, AppliedTemplateGeneration: 2, MaxUnavailable: 1, UpdateStrategy: "DEFAULT", Created: time.Unix(123, 0).UTC(), Workers: []domain.NodegroupWorker{{InstanceID: "i-original", NodeName: "i-original", NodeUID: "original-node-uid", PrivateIP: "10.0.0.5", LifecycleState: "InService", Ready: true}}}
			group.ScaleDownStarted, group.ScaleDownScaleUpVersion = true, 39
			// An already admitted health-replacement drain must survive a config
			// update, its cancellation, and recovery into nodegroup deletion.
			group.Workers[0].DrainStarted = time.Unix(200, 0).UTC()
			group.Workers[0].DrainCompleted = time.Unix(260, 0).UTC()
			group.Workers[0].Unschedulable = true
			foreign := group
			foreign.Key.Cluster.AccountID = "222222222222"
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutCluster(cluster); err != nil {
					return err
				}
				other := cluster
				other.Key = foreign.Key.Cluster
				if err := tx.PutCluster(other); err != nil {
					return err
				}
				if err := tx.PutNodegroup(foreign); err != nil {
					return err
				}
				return tx.PutNodegroup(group)
			}); err != nil {
				t.Fatal(err)
			}
			if stores.restart != nil {
				stores.restart()
			}
			service := domain.New(domain.Config{Repository: stores.repo})
			defer func() { _ = service.Close() }()
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Cluster.Partition, AccountID: key.Cluster.AccountID, Region: key.Cluster.Region, PrincipalARN: "arn:aws:iam::" + key.Cluster.AccountID + ":root", PrincipalID: key.Cluster.AccountID})
			model, _ := awscatalog.LookupService("eks")
			call := func(operation string, input any) (any, *awswire.Error) {
				op, _ := model.Operation(operation)
				return service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
			}
			invalid := &api.UpdateNodegroupConfigRequest{ClusterName: new(api.String(key.Cluster.Name)), NodegroupName: new(api.String(key.Name)), Labels: &api.UpdateLabelsPayload{AddOrUpdateLabels: api.LabelsMap{"leaked": "mutation"}}, ScalingConfig: &api.NodegroupScalingConfig{DesiredSize: new(api.ZeroCapacity(3))}}
			if _, rejected := call("UpdateNodegroupConfig", invalid); rejected == nil || rejected.Code != "InvalidParameterException" {
				t.Fatalf("invalid scaling accepted: %v", rejected)
			}
			if err := stores.repo.View(t.Context(), func(tx domain.Reader) error {
				retained, err := tx.Nodegroup(key)
				if err != nil {
					return err
				}
				if retained.Labels["leaked"] != "" || retained.Generation != group.Generation {
					t.Fatal("rejected request leaked desired mutation")
				}
				if !retained.ScaleDownStarted || retained.ScaleDownScaleUpVersion != 39 {
					t.Fatal("restart or rejected update lost the retained scale-down fence")
				}
				updates, err := tx.NodegroupUpdates(key)
				if err != nil {
					return err
				}
				if len(updates) != 0 {
					t.Fatal("rejected request created an update")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			request := &api.UpdateNodegroupConfigRequest{ClusterName: new(api.String(key.Cluster.Name)), NodegroupName: new(api.String(key.Name)), ClientRequestToken: new(api.String("stable-config-token")), Labels: &api.UpdateLabelsPayload{AddOrUpdateLabels: api.LabelsMap{"kept": "changed"}}}
			result, rejected := call("UpdateNodegroupConfig", request)
			if rejected != nil {
				t.Fatal(rejected)
			}
			updateID := string(*result.(*api.UpdateNodegroupConfigResponse).Update.Id)
			if _, rejected = call("DeleteNodegroup", &api.DeleteNodegroupRequest{ClusterName: request.ClusterName, NodegroupName: request.NodegroupName}); rejected != nil {
				t.Fatal(rejected)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			if stores.restart != nil {
				stores.restart()
			}
			service = domain.New(domain.Config{Repository: stores.repo})
			replay, rejected := call("UpdateNodegroupConfig", request)
			if rejected != nil {
				t.Fatal(rejected)
			}
			replayed := replay.(*api.UpdateNodegroupConfigResponse).Update
			if string(*replayed.Id) != updateID || string(*replayed.Status) != "Cancelled" {
				t.Fatalf("replay resurrected cancelled update: %#v", replayed)
			}
			check := func(tx domain.Reader) error {
				retained, err := tx.Nodegroup(key)
				if err != nil {
					return err
				}
				if retained.Status != "DELETING" || retained.Operation != "delete" || retained.Workers[0].NodeUID != "original-node-uid" {
					t.Fatalf("lost resumable deletion: %#v", retained)
				}
				if retained.ScaleDownStarted || retained.ScaleDownScaleUpVersion != 0 {
					t.Fatal("newly admitted config update retained the preceding scale-down phase")
				}
				worker := retained.Workers[0]
				if !worker.DrainStarted.Equal(group.Workers[0].DrainStarted) || !worker.DrainCompleted.Equal(group.Workers[0].DrainCompleted) || !worker.Unschedulable {
					t.Fatalf("operation transition reset a reserved drain: %#v", worker)
				}
				unchanged, err := tx.Nodegroup(foreign.Key)
				if err != nil {
					return err
				}
				if unchanged.Status != "ACTIVE" || unchanged.Labels["kept"] != "original" || !unchanged.ScaleDownStarted || unchanged.ScaleDownScaleUpVersion != 39 {
					t.Fatal("nodegroup mutation crossed account")
				}
				update, err := tx.NodegroupUpdate(key, updateID)
				if err != nil {
					return err
				}
				if update.Status != "Cancelled" {
					t.Fatal("update cancellation was not atomic with deletion admission")
				}
				return nil
			}
			if err := stores.repo.View(t.Context(), check); err != nil {
				t.Fatal(err)
			}
			rollback := errors.New("abort parent deletion")
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.DeleteCluster(key.Cluster); err != nil {
					return err
				}
				return rollback
			}); !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			if err := stores.repo.View(t.Context(), check); err != nil {
				t.Fatal(err)
			}
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteCluster(key.Cluster) }); err != nil {
				t.Fatal(err)
			}
			if err := stores.repo.View(t.Context(), func(tx domain.Reader) error {
				if _, err := tx.Nodegroup(key); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("cluster deletion retained nodegroup: %v", err)
				}
				if _, err := tx.NodegroupUpdate(key, updateID); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("cluster deletion retained nodegroup update: %v", err)
				}
				_, err := tx.Nodegroup(foreign.Key)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodegroupConfigParamsDescribeAdmittedRequestAfterRestart(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			stores := openRepositories(t, kind)
			key := domain.NodegroupKey{Cluster: clusterKey(), Name: "workers"}
			group := domain.Nodegroup{Key: key, ID: "group-incarnation", ClusterID: "control-incarnation", Status: "ACTIVE", Version: "1.33", Subnets: []string{"subnet-a"}, Labels: map[string]string{"obsolete": "old"}, MinSize: 0, MaxSize: 5, DesiredSize: 3, MaxUnavailable: 1, UpdateStrategy: "DEFAULT", Generation: 1}
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutCluster(domain.Cluster{Key: key.Cluster, ID: group.ClusterID, Status: "ACTIVE", KubernetesVersion: "1.33"}); err != nil {
					return err
				}
				return tx.PutNodegroup(group)
			}); err != nil {
				t.Fatal(err)
			}
			service := domain.New(domain.Config{Repository: stores.repo})
			defer func() { _ = service.Close() }()
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Cluster.Partition, AccountID: key.Cluster.AccountID, Region: key.Cluster.Region, PrincipalARN: "arn:aws:iam::" + key.Cluster.AccountID + ":root", PrincipalID: key.Cluster.AccountID})
			model, _ := awscatalog.LookupService("eks")
			call := func(operation string, input any) any {
				t.Helper()
				op, _ := model.Operation(operation)
				out, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
				if rejected != nil {
					t.Fatal(rejected)
				}
				return out
			}
			// Field/type names follow the retained generated EKS UpdateParam model.
			// JSON parameter values are compared structurally, not by incidental spacing.
			var first api.UpdateNodegroupConfigRequest
			if err := json.Unmarshal([]byte(`{
				"clientRequestToken":"first-request",
				"labels":{"addOrUpdateLabels":{"workload":"first"},"removeLabels":["obsolete"]},
				"taints":{"addOrUpdateTaints":[{"key":"dedicated","value":"batch","effect":"NO_SCHEDULE"}],"removeTaints":[{"key":"old","value":"batch","effect":"NO_EXECUTE"}]},
				"scalingConfig":{"minSize":0,"maxSize":5,"desiredSize":3},
				"updateConfig":{"maxUnavailable":2,"updateStrategy":"MINIMAL"}
			}`), &first); err != nil {
				t.Fatal(err)
			}
			first.ClusterName, first.NodegroupName = new(api.String(key.Cluster.Name)), new(api.String(key.Name))
			firstUpdate := call("UpdateNodegroupConfig", &first).(*api.UpdateNodegroupConfigResponse).Update
			assertParams := func(update *api.Update, expectedJSON string) {
				t.Helper()
				got := map[string]any{}
				for _, p := range update.Params {
					if p.Type == nil || p.Value == nil {
						t.Fatal("update parameter is missing its modeled type or value")
					}
					var v any
					if err := json.Unmarshal([]byte(*p.Value), &v); err != nil {
						v = string(*p.Value)
					}
					got[string(*p.Type)] = v
				}
				var want map[string]any
				if err := json.Unmarshal([]byte(expectedJSON), &want); err != nil {
					t.Fatal(err)
				}
				if len(update.Params) != len(want) || !reflect.DeepEqual(got, want) {
					t.Fatalf("admitted request parameters = %#v, want %#v", got, want)
				}
			}
			firstParams := `{"LabelsToAdd":{"workload":"first"},"LabelsToRemove":["obsolete"],"TaintsToAdd":[{"key":"dedicated","value":"batch","effect":"NO_SCHEDULE"}],"TaintsToRemove":[{"key":"old","value":"batch","effect":"NO_EXECUTE"}],"MinSize":0,"MaxSize":5,"DesiredSize":3,"MaxUnavailable":2,"UpdateStrategy":"MINIMAL"}`
			assertParams(firstUpdate, firstParams)
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			// Install completed history only after the effect loop has stopped;
			// an in-flight completion must not race this repository fixture.
			if err := stores.repo.Update(t.Context(), func(tx domain.Transaction) error {
				n, err := tx.Nodegroup(key)
				if err != nil {
					return err
				}
				u, err := tx.NodegroupUpdate(key, string(*firstUpdate.Id))
				if err != nil {
					return err
				}
				u.Status = "Successful"
				if err = tx.PutNodegroupUpdate(u); err != nil {
					return err
				}
				n.Status, n.Operation, n.UpdateID = "ACTIVE", "", ""
				return tx.PutNodegroup(n)
			}); err != nil {
				t.Fatal(err)
			}
			service = domain.New(domain.Config{Repository: stores.repo})
			second := &api.UpdateNodegroupConfigRequest{ClusterName: first.ClusterName, NodegroupName: first.NodegroupName, ClientRequestToken: new(api.String("second-request")), Labels: &api.UpdateLabelsPayload{AddOrUpdateLabels: api.LabelsMap{"workload": "second"}}, ScalingConfig: &api.NodegroupScalingConfig{DesiredSize: new(api.ZeroCapacity(1))}, UpdateConfig: &api.NodegroupUpdateConfig{MaxUnavailablePercentage: new(api.PercentCapacity(50))}}
			secondUpdate := call("UpdateNodegroupConfig", second).(*api.UpdateNodegroupConfigResponse).Update
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			if stores.restart != nil {
				stores.restart()
			}
			service = domain.New(domain.Config{Repository: stores.repo})
			replayed := call("UpdateNodegroupConfig", &first).(*api.UpdateNodegroupConfigResponse).Update
			if string(*replayed.Id) != string(*firstUpdate.Id) || string(*replayed.Status) != "Successful" {
				t.Fatalf("replay did not retain the original completed update: %#v", replayed)
			}
			assertParams(replayed, firstParams)
			described := call("DescribeUpdate", &api.DescribeUpdateRequest{Name: first.ClusterName, NodegroupName: first.NodegroupName, UpdateId: firstUpdate.Id}).(*api.DescribeUpdateResponse).Update
			assertParams(described, firstParams)
			described = call("DescribeUpdate", &api.DescribeUpdateRequest{Name: first.ClusterName, NodegroupName: first.NodegroupName, UpdateId: secondUpdate.Id}).(*api.DescribeUpdateResponse).Update
			assertParams(described, `{"LabelsToAdd":{"workload":"second"},"DesiredSize":1,"MaxUnavailablePercentage":50}`)
			first.UpdateConfig.MaxUnavailable = new(api.NonZeroInteger(3))
			op, _ := model.Operation("UpdateNodegroupConfig")
			if _, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: &first}); rejected == nil || rejected.Code != "InvalidParameterException" {
				t.Fatalf("changed token replay accepted: %v", rejected)
			}
		})
	}
}
