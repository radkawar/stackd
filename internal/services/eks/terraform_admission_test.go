package eks

import (
	"testing"

	api "stackd/internal/awsapi/eks"
)

func TestTerraformBootstrapSelfManagedAddons(t *testing.T) {
	for _, row := range []struct {
		name      string
		enabled   *api.BoxedBoolean
		wantError bool
	}{
		{name: "omitted"},
		{name: "provider-default", enabled: new(api.BoxedBoolean(true))},
		{name: "disable-native-baseline", enabled: new(api.BoxedBoolean(false)), wantError: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := validateBootstrapSelfManagedAddons(row.enabled)
			if (err != nil) != row.wantError {
				t.Fatalf("bootstrap admission = %v, want error %v", err, row.wantError)
			}
		})
	}
}

func TestTerraformDisabledAutoModeDefaults(t *testing.T) {
	for _, row := range []struct {
		name      string
		compute   *api.ComputeConfigRequest
		network   *api.KubernetesNetworkConfigRequest
		storage   *api.StorageConfigRequest
		wantError bool
	}{
		{name: "omitted"},
		{name: "provider-defaults", compute: &api.ComputeConfigRequest{Enabled: new(api.BoxedBoolean(false))}, network: &api.KubernetesNetworkConfigRequest{ElasticLoadBalancing: &api.ElasticLoadBalancing{Enabled: new(api.BoxedBoolean(false))}}, storage: &api.StorageConfigRequest{BlockStorage: &api.BlockStorage{Enabled: new(api.BoxedBoolean(false))}}},
		{name: "compute-enabled", compute: &api.ComputeConfigRequest{Enabled: new(api.BoxedBoolean(true))}, wantError: true},
		{name: "compute-pools", compute: &api.ComputeConfigRequest{NodePools: api.StringList{"general-purpose"}}, wantError: true},
		{name: "compute-role", compute: &api.ComputeConfigRequest{NodeRoleArn: new(api.String("arn:aws:iam::738492615083:role/node"))}, wantError: true},
		{name: "lb-enabled", network: &api.KubernetesNetworkConfigRequest{ElasticLoadBalancing: &api.ElasticLoadBalancing{Enabled: new(api.BoxedBoolean(true))}}, wantError: true},
		{name: "network-override", network: &api.KubernetesNetworkConfigRequest{ServiceIpv4Cidr: new(api.String("10.44.0.0/16"))}, wantError: true},
		{name: "storage-enabled", storage: &api.StorageConfigRequest{BlockStorage: &api.BlockStorage{Enabled: new(api.BoxedBoolean(true))}}, wantError: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := validateDisabledAutoMode(row.compute, row.network, row.storage); (err != nil) != row.wantError {
				t.Fatalf("Auto Mode admission = %v, want error %v", err, row.wantError)
			}
		})
	}
}

func TestTerraformEmptyLogSelectionsDoNotChangeLogging(t *testing.T) {
	for _, row := range []struct {
		name      string
		current   []string
		logging   *api.Logging
		want      []string
		wantError bool
	}{
		{name: "provider-disabled-default", logging: &api.Logging{ClusterLogging: []api.LogSetup{
			{Enabled: new(api.BoxedBoolean(true)), Types: []api.LogType{}},
			{Enabled: new(api.BoxedBoolean(false)), Types: []api.LogType{"api", "audit", "authenticator", "controllerManager", "scheduler"}},
		}}},
		{name: "empty-enable", current: []string{"api"}, logging: &api.Logging{ClusterLogging: []api.LogSetup{{Enabled: new(api.BoxedBoolean(true))}}}, want: []string{"api"}},
		{name: "empty-disable", current: []string{"api"}, logging: &api.Logging{ClusterLogging: []api.LogSetup{{Enabled: new(api.BoxedBoolean(false)), Types: []api.LogType{}}}}, want: []string{"api"}},
		{name: "selected-disable", current: []string{"api"}, logging: &api.Logging{ClusterLogging: []api.LogSetup{{Enabled: new(api.BoxedBoolean(false)), Types: []api.LogType{"api"}}}}},
		{name: "missing-enabled", logging: &api.Logging{ClusterLogging: []api.LogSetup{{Types: []api.LogType{"api"}}}}, wantError: true},
		{name: "invalid-type", logging: &api.Logging{ClusterLogging: []api.LogSetup{{Enabled: new(api.BoxedBoolean(true)), Types: []api.LogType{"unknown"}}}}, wantError: true},
		{name: "duplicate-type", logging: &api.Logging{ClusterLogging: []api.LogSetup{
			{Enabled: new(api.BoxedBoolean(true)), Types: []api.LogType{"api"}},
			{Enabled: new(api.BoxedBoolean(false)), Types: []api.LogType{"api"}},
		}}, wantError: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, err := mergeLogging(row.current, row.logging)
			if (err != nil) != row.wantError {
				t.Fatalf("logging admission = %v, want error %v", err, row.wantError)
			}
			if len(got) != len(row.want) {
				t.Fatalf("enabled logging = %v, want %v", got, row.want)
			}
			for i := range got {
				if got[i] != row.want[i] {
					t.Fatalf("enabled logging = %v, want %v", got, row.want)
				}
			}
		})
	}
}
