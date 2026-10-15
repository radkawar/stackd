package kafka

import (
	"context"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/kafka"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"testing"
)

func TestTerraformDefaultPlacementRequiresRealSubnets(t *testing.T) {
	input := &api.ProvisionedRequest{BrokerNodeGroupInfo: &api.BrokerNodeGroupInfo{}}
	text(&input.BrokerNodeGroupInfo.InstanceType, "kafka.local")
	text(&input.BrokerNodeGroupInfo.BrokerAZDistribution, "DEFAULT")
	text(&input.EnhancedMonitoring, "DEFAULT")
	cluster := ClusterRecord{Brokers: 2}
	if err := admitProvisioned(input, &cluster); err == nil {
		t.Fatal("DEFAULT placement without a real subnet owner was accepted")
	}
	input.BrokerNodeGroupInfo.ClientSubnets = append(input.BrokerNodeGroupInfo.ClientSubnets, "subnet-b", "subnet-a")
	input.BrokerNodeGroupInfo.SecurityGroups = append(input.BrokerNodeGroupInfo.SecurityGroups, "sg-native")
	if err := admitProvisioned(input, &cluster); err != nil {
		t.Fatal(err)
	}
	if !cluster.DefaultMetrics || len(cluster.ClientSubnets) != 2 || cluster.ClientSubnets[0] != "subnet-a" || len(cluster.SecurityGroups) != 1 {
		t.Fatalf("native intent was discarded: %#v", cluster)
	}
	input.EnhancedMonitoring = nil
	cluster = ClusterRecord{Brokers: 2}
	if err := admitProvisioned(input, &cluster); err != nil {
		t.Fatal(err)
	}
	if !cluster.DefaultMetrics {
		t.Fatal("omitting enhanced monitoring disabled DEFAULT metrics")
	}
	cluster = ClusterRecord{Brokers: 3}
	if err := admitProvisioned(input, &cluster); err == nil {
		t.Fatal("unequal DEFAULT subnet distribution was accepted")
	}
	text(&input.EnhancedMonitoring, "PER_TOPIC_PER_BROKER")
	cluster = ClusterRecord{Brokers: 2}
	if err := admitProvisioned(input, &cluster); err == nil {
		t.Fatal("unimplemented monitoring effects were accepted")
	}
}

func TestBrokerNetworkMemoryStateHasIndependentSlices(t *testing.T) {
	original := ClusterRecord{ClientSubnets: []string{"subnet-a"}, SecurityGroups: []string{"sg-a"}, BrokerNetworks: []BrokerNetworkRecord{{BrokerID: 1, InterfaceID: "eni-owned", NetworkID: "vpc-owned"}}}
	copy := cloneCluster(original)
	copy.ClientSubnets[0] = "changed"
	copy.SecurityGroups[0] = "changed"
	copy.BrokerNetworks[0].InterfaceID = "changed"
	if original.ClientSubnets[0] != "subnet-a" || original.SecurityGroups[0] != "sg-a" || original.BrokerNetworks[0].InterfaceID != "eni-owned" {
		t.Fatal("broker ownership slices aliased caller memory")
	}
}

func TestNativeSpecificationRejectsPartialBrokerAttachments(t *testing.T) {
	spec := Specification{ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/owned/id", Incarnation: "id", Partition: "aws", AccountID: "111111111111", Region: "us-east-1", KafkaVersion: "3.7.1", Brokers: 2, SecurityMode: "TLS", Networks: []BrokerNetwork{{}}}
	if err := ValidateSpecification(spec); err == nil {
		t.Fatal("partial native broker attachment set was accepted")
	}
	spec.Networks = append(spec.Networks, BrokerNetwork{})
	if err := ValidateSpecification(spec); err != nil {
		t.Fatal(err)
	}
}

func TestKafkaRuntimeSourceRoleMatchesActualManagedEffects(t *testing.T) {
	cluster := ClusterRecord{Scope: Scope{"aws", "111111111111", "us-east-1"}, ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/owned/id"}
	caller := awsctx.WithMetadata(t.Context(), awsctx.Metadata{IssuerARN: "unrelated-caller-role"})
	metadata := awsctx.FromContext(runtimeContext(caller, cluster))
	if metadata.IssuerARN != "" || metadata.InvokedBy != "kafka.amazonaws.com" || metadata.ServicePrincipal.SourceARN != cluster.ARN {
		t.Fatal("local native context retained an unrelated caller role or lost source ownership")
	}
	cluster.DefaultMetrics = true
	metadata = awsctx.FromContext(runtimeContext(caller, cluster))
	if metadata.IssuerARN != "arn:aws:iam::111111111111:role/aws-service-role/kafka.amazonaws.com/AWSServiceRoleForKafka" || metadata.ServicePrincipal.SourceARN != cluster.ARN {
		t.Fatal("managed native effects lost their exact Kafka source role")
	}
}

func TestKafkaRoleUsageRetainsPendingNetworksAndMetrics(t *testing.T) {
	service := &Service{repository: NewMemoryRepository(nil)}
	for _, cluster := range []ClusterRecord{
		{Scope: Scope{"aws", "111111111111", "us-east-1"}, ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/network/id", Name: "network", State: "DELETING", ClientSubnets: []string{"subnet-owned"}},
		{Scope: Scope{"aws", "111111111111", "us-west-2"}, ARN: "arn:aws:kafka:us-west-2:111111111111:cluster/metrics/id", Name: "metrics", State: "CREATING", DefaultMetrics: true},
		{Scope: Scope{"aws", "111111111111", "us-east-1"}, ARN: "arn:aws:kafka:us-east-1:111111111111:cluster/local/id", Name: "local"},
		{Scope: Scope{"aws", "222222222222", "us-east-1"}, ARN: "arn:aws:kafka:us-east-1:222222222222:cluster/foreign/id", Name: "foreign", ClientSubnets: []string{"subnet-foreign"}},
	} {
		seedCluster(t, service, cluster)
	}
	if err := service.WithKafkaRoleUsage(t.Context(), "aws", "111111111111", func(_ context.Context, resources []string) error {
		seen := map[string]bool{}
		for _, arn := range resources {
			seen[arn] = true
		}
		if len(seen) != 2 || !seen["arn:aws:kafka:us-east-1:111111111111:cluster/network/id"] || !seen["arn:aws:kafka:us-west-2:111111111111:cluster/metrics/id"] {
			t.Fatalf("role usage lost pending/regional ownership or crossed account: %v", resources)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationReadAbsenceMatchesCapturedAWS(t *testing.T) {
	// controls.json absence-8 and missing-revision return this same HTTP400.
	authority := &revocableAuthorizer{}
	service := New(Config{Authorizer: authority})
	t.Cleanup(func() { _ = service.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	arn := "arn:aws:kafka:us-east-1:111111111111:configuration/owned/incarnation"
	model, _ := awscatalog.LookupService("kafka")
	read := func(name string, input any, denied bool) {
		t.Helper()
		op, _ := model.Operation(name)
		_, wire := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
		if denied {
			if wire == nil || wire.Code != "ForbiddenException" || wire.StatusCode != 403 {
				t.Fatalf("missing configuration bypassed current authority: %v", wire)
			}
			return
		}
		if wire == nil || wire.Code != "BadRequestException" || wire.StatusCode != 400 || wire.Message != "Configuration ARN does not exist." {
			t.Fatalf("configuration read absence differs from captured AWS: %v", wire)
		}
	}
	describe := &api.DescribeConfigurationInput{}
	text(&describe.Arn, arn)
	revision := &api.DescribeConfigurationRevisionInput{}
	text(&revision.Arn, arn)
	number(&revision.Revision, 99)
	read("DescribeConfiguration", describe, false)
	read("DescribeConfigurationRevision", revision, false)
	if err := service.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutConfiguration(ConfigurationRecord{Scope: scopeFor(ctx), ARN: arn, Name: "owned", LatestRevision: 1})
	}); err != nil {
		t.Fatal(err)
	}
	read("DescribeConfigurationRevision", revision, false)
	authority.denied = true
	read("DescribeConfiguration", describe, true)
	read("DescribeConfigurationRevision", revision, true)
}
