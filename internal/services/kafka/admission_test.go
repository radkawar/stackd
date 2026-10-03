package kafka

import (
	"stackd/clock"
	api "stackd/internal/awsapi/kafka"
	"stackd/internal/awsctx"
	"testing"
	"time"
)

func TestCreateAdmitsOrdinaryNamesButRejectsInertNetworking(t *testing.T) {
	for _, networked := range []bool{false, true} {
		name := "stackd-native"
		if networked {
			name += "-vpc"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			s := New(Config{Clock: clock.NewManual(now), Runtime: controlledRuntime{}, Authorizer: &revocableAuthorizer{}})
			defer s.Close()
			in := &api.CreateClusterInput{BrokerNodeGroupInfo: &api.BrokerNodeGroupInfo{}}
			text(&in.ClusterName, name)
			text(&in.KafkaVersion, "3.7.1")
			number(&in.NumberOfBrokerNodes, 1)
			text(&in.BrokerNodeGroupInfo.InstanceType, "kafka.local")
			if networked {
				stringList(&in.BrokerNodeGroupInfo.ClientSubnets, []string{"subnet-not-enforced"})
			}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
			var out *api.CreateClusterOutput
			e := s.repository.Attempt(ctx, func(tx Transaction) error { var e error; out, e = s.createCluster(tx.Context(), tx, in); return e })
			if networked {
				if e == nil || wireError(e).Code != "BadRequestException" {
					t.Fatalf("unenforced subnet admitted: %+v %v", out, e)
				}
			} else if e != nil || out == nil || out.State == nil || *out.State != api.ClusterStateCREATING {
				t.Fatalf("ordinary cluster name rejected: %+v %v", out, e)
			}
			if e = s.repository.View(ctx, func(r Reader) error {
				rows, e := r.Clusters(scopeFor(ctx))
				if e != nil {
					return e
				}
				if networked && len(rows) != 0 {
					t.Fatalf("rejected networking committed a cluster: %#v", rows)
				}
				if !networked && (len(rows) != 1 || rows[0].Name != name || rows[0].Incarnation == "") {
					t.Fatalf("accepted cluster lost its immutable native intent: %#v", rows)
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestRebootSelectsOneBrokerAndRejectsOverlappingHealing(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now), Runtime: controlledRuntime{}, Authorizer: &revocableAuthorizer{}})
	defer s.Close()
	v := retainedCluster(now)
	v.Brokers, v.State, v.Operation = 3, "ACTIVE", ""
	seedCluster(t, s, v)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region})
	in := &api.RebootBrokerInput{}
	text(&in.ClusterArn, v.ARN)
	stringList(&in.BrokerIds, []string{"1", "2", "3"})
	if e := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, e := s.reboot(tx.Context(), tx, in)
		return e
	}); e == nil {
		t.Fatal("multi-broker reboot was accepted")
	}
	stringList(&in.BrokerIds, []string{"2"})
	if e := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, e := s.reboot(tx.Context(), tx, in)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	got := readCluster(t, s, v.ARN)
	if got.State != "HEALING" || got.RebootBrokerID != 2 || got.Operation != "REBOOT_BROKER" {
		t.Fatalf("selected reboot intent was lost: %#v", got)
	}
	stringList(&in.BrokerIds, []string{"1"})
	if e := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, e := s.reboot(tx.Context(), tx, in)
		return e
	}); e == nil {
		t.Fatal("overlapping reboot was accepted while healing")
	}
	after := readCluster(t, s, v.ARN)
	if after.Version != got.Version || after.RebootBrokerID != 2 {
		t.Fatalf("rejected reboot changed selected native intent: %#v", after)
	}
}
