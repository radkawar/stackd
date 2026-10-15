package elbv2

import (
	"context"
	"net/url"
	"testing"
	"time"

	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/awsctx"
)

// These are generated Query/control-plane regressions, not native ALB evidence.
func TestTerraformLoadBalancerReadBoundaries(t *testing.T) {
	ctx := controlContext(t)
	s := New(Config{})
	defer s.Close()
	sc := scopeFor(ctx)
	a := arn(sc, "loadbalancer/app/terraform/0000000000000001")
	lb := LoadBalancerRecord{Scope: sc, IdleTimeout: 60 * time.Second}
	text(&lb.Data.LoadBalancerArn, a)
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutLoadBalancer(lb) }); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"LoadBalancerArn": {a}}
	out, err := controlCall(t, s, ctx, "DescribeCapacityReservation", q)
	if err != nil {
		t.Fatal(err)
	}
	capacity := out.(*api.DescribeCapacityReservationOutput)
	if capacity.MinimumLoadBalancerCapacity != nil || capacity.LastModifiedTime != nil || capacity.DecreaseRequestsRemaining != nil || len(capacity.CapacityReservationState) != 0 {
		t.Fatalf("fabricated capacity reservation: %#v", capacity)
	}
	for _, key := range []string{"access_logs.s3.enabled", "connection_logs.s3.enabled", "health_check_logs.s3.enabled"} {
		out, err = controlCall(t, s, ctx, "ModifyLoadBalancerAttributes", url.Values{"LoadBalancerArn": {a}, "Attributes.member.1.Key": {key}, "Attributes.member.1.Value": {"false"}})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, attribute := range out.(*api.ModifyLoadBalancerAttributesOutput).Attributes {
			if value(attribute.Key) == key && value(attribute.Value) == "false" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing disabled log readback: %s", key)
		}
		_, err = controlCall(t, s, ctx, "ModifyLoadBalancerAttributes", url.Values{"LoadBalancerArn": {a}, "Attributes.member.1.Key": {key}, "Attributes.member.1.Value": {"true"}})
		if err == nil || wireError(err).Code != "UnsupportedOperation" {
			t.Fatalf("unimplemented delivery admitted for %s: %v", key, err)
		}
	}
	// A provider-default batch must roll back a preceding supported mutation,
	// not hide an unsupported native effect behind successful metadata storage.
	_, err = controlCall(t, s, ctx, "ModifyLoadBalancerAttributes", url.Values{"LoadBalancerArn": {a}, "Attributes.member.1.Key": {"idle_timeout.timeout_seconds"}, "Attributes.member.1.Value": {"120"}, "Attributes.member.2.Key": {"routing.http.desync_mitigation_mode"}, "Attributes.member.2.Value": {"defensive"}})
	if err == nil || wireError(err).Code != "UnsupportedOperation" {
		t.Fatalf("unimplemented desync mode admitted: %v", err)
	}
	if err := s.repository.View(ctx, func(tx Reader) error {
		stored, err := tx.LoadBalancer(sc, a)
		if err == nil && stored.IdleTimeout != 60*time.Second {
			t.Fatal("failed attribute batch changed idle timeout")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, other := range []context.Context{
		awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: sc.Partition, AccountID: "999999999999", Region: sc.Region, PrincipalARN: "arn:aws:iam::999999999999:root", PrincipalID: "999999999999"}),
		awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: sc.Partition, AccountID: sc.AccountID, Region: "us-west-2", PrincipalARN: "arn:aws:iam::" + sc.AccountID + ":root", PrincipalID: sc.AccountID}),
	} {
		if _, err := controlCall(t, s, other, "DescribeCapacityReservation", q); err == nil {
			t.Fatal("capacity read crossed account/region")
		}
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteLoadBalancer(sc, a) }); err != nil {
		t.Fatal(err)
	}
	if _, err := controlCall(t, s, ctx, "DescribeCapacityReservation", q); err == nil || wireError(err).Code != "LoadBalancerNotFound" {
		t.Fatalf("deleted reservation scope returned success: %v", err)
	}
}
