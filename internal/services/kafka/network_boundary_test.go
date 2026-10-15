package kafka

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/kafka"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type boundaryRuntime struct {
	controlledRuntime
	quarantine func(context.Context, Specification) error
}

func (r boundaryRuntime) Quarantine(ctx context.Context, spec Specification) error {
	return r.quarantine(ctx, spec)
}
func (boundaryRuntime) ReadMetrics(context.Context, Specification) ([]BrokerMetric, error) {
	return nil, errors.New("unexpected native metric read")
}

type boundaryNetworks struct {
	observation error
	allocations int
}

func (n *boundaryNetworks) AllocateBrokerNetwork(context.Context, BrokerNetworkRequest) (BrokerNetwork, error) {
	n.allocations++
	return BrokerNetwork{}, errors.New("unexpected network allocation")
}
func (n *boundaryNetworks) ObserveBrokerNetwork(context.Context, BrokerNetworkIdentity, string) (BrokerNetwork, error) {
	return BrokerNetwork{}, n.observation
}
func (*boundaryNetworks) ReleaseBrokerNetwork(context.Context, BrokerNetworkIdentity, string) error {
	return errors.New("unexpected network release")
}

type boundaryMetrics struct{}

func (boundaryMetrics) PublishKafkaMetrics(context.Context, Scope, string, []BrokerMetric) error {
	return errors.New("unexpected metric publication")
}

func TestInitialNetworkObservationFailureQuarantinesOutsideTransaction(t *testing.T) {
	for _, operation := range []string{"health", "describe"} {
		t.Run(operation, func(t *testing.T) {
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			cluster := retainedCluster(now)
			cluster.State, cluster.Operation, cluster.Brokers = "ACTIVE", "", 2
			cluster.ClientSubnets = []string{"subnet-a", "subnet-b"}
			cluster.BrokerNetworks = []BrokerNetworkRecord{{BrokerID: 1, InterfaceID: "eni-a", SubnetID: "subnet-a", NetworkID: "vpc-owned"}, {BrokerID: 2, InterfaceID: "eni-b", SubnetID: "subnet-b", NetworkID: "vpc-owned"}}
			cluster.Endpoint = Endpoint{SecurityMode: "PLAINTEXT", Brokers: []Broker{{ID: 1, Address: "10.50.0.10:9092"}, {ID: 2, Address: "10.50.1.10:9092"}}}
			quarantined := false
			var service *Service
			runtime := boundaryRuntime{quarantine: func(ctx context.Context, spec Specification) error {
				if spec.ARN != cluster.ARN || spec.Incarnation != cluster.Incarnation || len(spec.Networks) != 2 || spec.Networks[1].InterfaceID != "eni-b" {
					t.Fatal("quarantine lost exact retained ownership")
				}
				if err := service.repository.Update(ctx, func(tx Transaction) error { _, err := tx.Cluster(cluster.ARN); return err }); err != nil {
					return err
				}
				quarantined = true
				return nil
			}}
			service = New(Config{Clock: clock.NewManual(now), Runtime: runtime, Networks: &boundaryNetworks{observation: errors.New("native network cannot use the selected IPv6 DHCP DNS")}, Authorizer: &revocableAuthorizer{}})
			t.Cleanup(func() { _ = service.Close() })
			seedCluster(t, service, cluster)
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: cluster.Partition, AccountID: cluster.AccountID, Region: cluster.Region})
			if operation == "health" {
				job, found, err := (clusterJobs{service}).Next(ctx)
				if err != nil || !found {
					t.Fatalf("missing health job: %v", err)
				}
				if err := (clusterJobs{service}).Run(ctx, job); err != nil {
					t.Fatal(err)
				}
			} else if err := service.observe(ctx, cluster.ARN, "DescribeCluster"); err != nil {
				t.Fatal(err)
			}
			retained := readCluster(t, service, cluster.ARN)
			if !quarantined || retained.State != "FAILED" || len(retained.Endpoint.Brokers) != 0 || retained.Incarnation != cluster.Incarnation {
				t.Fatalf("failed prerequisite retained a serving endpoint: %+v", retained)
			}
		})
	}
}

type boundaryRoleFailure struct {
	cause  error
	record func(context.Context) error
}

func (e *boundaryRoleFailure) Error() string                             { return e.cause.Error() }
func (e *boundaryRoleFailure) Unwrap() error                             { return e.cause }
func (e *boundaryRoleFailure) RecordRejection(ctx context.Context) error { return e.record(ctx) }

type boundaryRoles struct {
	failure error
	cancel  context.CancelFunc
}

func (r boundaryRoles) EnsureServiceLinkedRole(context.Context, string) error {
	r.cancel()
	return r.failure
}

func TestDeniedAutomaticRoleCompletesAfterRollbackAndCallerCancellation(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}))
	defer cancel()
	completed := false
	var service *Service
	dependency := &boundaryRoleFailure{cause: &awswire.Error{Code: "AccessDenied", Message: "iam:CreateServiceLinkedRole denied", StatusCode: 403}, record: func(completion context.Context) error {
		if completion.Err() != nil {
			return completion.Err()
		}
		if err := service.repository.Update(completion, func(tx Transaction) error {
			clusters, err := tx.AllClusters()
			if err == nil && len(clusters) != 0 {
				return errors.New("denied cluster was committed")
			}
			return err
		}); err != nil {
			return err
		}
		completed = true
		return nil
	}}
	networks := &boundaryNetworks{}
	service = New(Config{Clock: clock.NewManual(now), Runtime: boundaryRuntime{}, Networks: networks, Metrics: boundaryMetrics{}, ServiceLinkedRoles: boundaryRoles{failure: fmt.Errorf("automatic IAM dependency: %w", dependency), cancel: cancel}, Authorizer: &revocableAuthorizer{}})
	t.Cleanup(func() { _ = service.Close() })
	input := &api.CreateClusterInput{BrokerNodeGroupInfo: &api.BrokerNodeGroupInfo{}}
	text(&input.ClusterName, "denied-role")
	text(&input.KafkaVersion, "3.7.1")
	number(&input.NumberOfBrokerNodes, 2)
	text(&input.BrokerNodeGroupInfo.InstanceType, "kafka.local")
	stringList(&input.BrokerNodeGroupInfo.ClientSubnets, []string{"subnet-a", "subnet-b"})
	ctx = awsapi.WithDecodedRequest(ctx, awsapi.DecodedRequest{Input: input})
	_, rejected := service.operations["CreateCluster"](ctx)
	if rejected == nil || rejected.Code != "AccessDenied" || !completed || networks.allocations != 0 {
		t.Fatalf("IAM rejection lost completion or escaped rollback: %v completed=%t allocations=%d", rejected, completed, networks.allocations)
	}
}
