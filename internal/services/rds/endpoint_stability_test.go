package rds

import (
	"context"
	"testing"
	"time"

	"stackd/clock"
	engine "stackd/engine/rds"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/rds"
	"stackd/internal/awscatalog"
)

// A credential-store deadline is not evidence that the published SQL process
// stopped. Control-plane reads must not turn it into a lifecycle transition.
type unavailableReadCipher struct{ testCipher }

func (unavailableReadCipher) Open(context.Context, string, []byte) (string, string, error) {
	return "", "", context.DeadlineExceeded
}

func TestPublishedEndpointSurvivesUnavailableReadProbe(t *testing.T) {
	for _, action := range []string{"DescribeDBInstances", "DescribeDBClusters", "ResolveDataCluster"} {
		t.Run(action, func(t *testing.T) {
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			s := New(Config{Clock: clock.NewManual(now), Runtime: controlledRuntime{}, Cipher: unavailableReadCipher{}})
			t.Cleanup(func() { _ = s.Close() })
			v := retainedDatabase(now)
			v.Status, v.Operation = "available", ""
			v.Due = now.Add(healthInterval)
			v.Endpoint = engine.Endpoint{Address: "127.0.0.1", Port: 15432, CA: []byte("retained-public-trust")}
			if action != "DescribeDBInstances" {
				v.Key.Kind, v.Engine, v.HTTPEnabled = "cluster", "aurora-postgresql", true
				member := v
				member.Key.Kind, member.Key.Name, member.Cluster = "db", "writer", v.Key.Name
				seedDatabase(t, s, member)
			}
			seedDatabase(t, s, v)
			ctx := globalCommandContext(t)
			if action == "ResolveDataCluster" {
				out, err := s.ResolveDataCluster(ctx, v.Key.ARN())
				if err != nil || out.Status != "available" || out.Endpoint.Address != v.Endpoint.Address || out.Endpoint.Port != v.Endpoint.Port {
					t.Fatalf("resolution lost the published endpoint: %+v, %v", out, err)
				}
			} else {
				model, _ := awscatalog.LookupService("rds")
				op, _ := model.Operation(action)
				var input any = &api.DescribeDBInstancesMessage{DBInstanceIdentifier: new(api.String(v.Key.Name))}
				if action == "DescribeDBClusters" {
					input = &api.DescribeDBClustersMessage{DBClusterIdentifier: new(api.String(v.Key.Name))}
				}
				out, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: input})
				if rejected != nil {
					t.Fatal(rejected)
				}
				switch out := out.(type) {
				case *api.DBInstanceMessage:
					if len(out.DBInstances) != 1 || value(out.DBInstances[0].DBInstanceStatus) != "available" || out.DBInstances[0].Endpoint == nil || value(out.DBInstances[0].Endpoint.Address) != v.Endpoint.Address || int32(*out.DBInstances[0].Endpoint.Port) != v.Endpoint.Port {
						t.Fatalf("describe lost the published instance endpoint: %+v", out)
					}
				case *api.DBClusterMessage:
					if len(out.DBClusters) != 1 || value(out.DBClusters[0].Status) != "available" || value(out.DBClusters[0].Endpoint) != v.Endpoint.Address || out.DBClusters[0].Port == nil || int32(*out.DBClusters[0].Port) != v.Endpoint.Port {
						t.Fatalf("describe lost the published cluster endpoint: %+v", out)
					}
				default:
					t.Fatalf("unexpected result %T", out)
				}
			}
			current := readDatabase(t, s, v.Key)
			if current.Status != v.Status || current.Operation != v.Operation || current.Version != v.Version || current.RuntimeID != v.RuntimeID || !current.Due.Equal(v.Due) {
				t.Fatalf("read changed lifecycle authority: %+v", current)
			}
		})
	}
}
