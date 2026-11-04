package integrations

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"stackd/compute/network"
	"stackd/internal/awsctx"
	"stackd/internal/services/elbv2"
)

type elbv2PodRouteAuthorityFunc func(context.Context, string, string, string, string) ([]network.PodRoute, error)

func (f elbv2PodRouteAuthorityFunc) PodRoutes(ctx context.Context, partition, account, region, vpc string) ([]network.PodRoute, error) {
	return f(ctx, partition, account, region, vpc)
}

func TestELBV2PodRoutesUsesCurrentExactScopeWithoutEC2PublicPolicy(t *testing.T) {
	scope := elbv2.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	routes := []network.PodRoute{{Prefix: netip.MustParsePrefix("10.42.0.0/24"), ClusterID: "cluster-current", OwnerToken: "owner", NodeName: "node", NodeUID: "node-uid", ResourceVersion: "17", ContainerID: "container", NetworkID: "network", WorkerIP: netip.MustParseAddr("172.22.0.3")}}
	calls := 0
	a := &ELBV2Networks{PodRouteAuthority: elbv2PodRouteAuthorityFunc(func(received context.Context, partition, account, region, vpc string) ([]network.PodRoute, error) {
		calls++
		if received != ctx || partition != scope.Partition || account != scope.AccountID || region != scope.Region || vpc != "vpc-current" {
			t.Fatalf("route authority received foreign context/scope: %s %s %s %s", partition, account, region, vpc)
		}
		return routes, nil
	})}
	got, err := a.PodRoutes(ctx, scope, "vpc-current")
	if err != nil || !slices.Equal(got, routes) {
		t.Fatalf("delegating current routes: %+v %v", got, err)
	}
	routes[0].WorkerIP = netip.MustParseAddr("172.22.0.4")
	if got[0].WorkerIP == routes[0].WorkerIP {
		t.Fatal("integration retained provider-owned route slice")
	}
	got, err = a.PodRoutes(ctx, scope, "vpc-current")
	if err != nil || calls != 2 || got[0].WorkerIP != routes[0].WorkerIP {
		t.Fatalf("integration cached stale authority: %+v calls=%d %v", got, calls, err)
	}
	a.PodRouteAuthority = elbv2PodRouteAuthorityFunc(func(context.Context, string, string, string, string) ([]network.PodRoute, error) {
		return routes, errors.New("current EKS authority unavailable")
	})
	if got, err := a.PodRoutes(ctx, scope, "vpc-current"); err == nil || len(got) != 0 {
		t.Fatalf("unavailable authority reused previous routes: %+v %v", got, err)
	}
}

func TestELBV2PodRoutesRejectsForeignScopeAndPreservesEC2OnlyVPC(t *testing.T) {
	scope := elbv2.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	a := &ELBV2Networks{}
	if routes, err := a.PodRoutes(ctx, scope, "vpc-current"); err != nil || len(routes) != 0 {
		t.Fatalf("EC2-only composition needs EKS observer: %+v %v", routes, err)
	}
	a.PodRouteAuthority = elbv2PodRouteAuthorityFunc(func(context.Context, string, string, string, string) ([]network.PodRoute, error) {
		t.Fatal("foreign request reached route authority")
		return nil, nil
	})
	for _, foreign := range []elbv2.Scope{
		{Partition: "aws-cn", AccountID: scope.AccountID, Region: scope.Region},
		{Partition: scope.Partition, AccountID: "222222222222", Region: scope.Region},
		{Partition: scope.Partition, AccountID: scope.AccountID, Region: "us-west-2"},
	} {
		if routes, err := a.PodRoutes(ctx, foreign, "vpc-current"); err == nil || len(routes) != 0 {
			t.Fatalf("foreign scope admitted: %+v %+v %v", foreign, routes, err)
		}
	}
}
