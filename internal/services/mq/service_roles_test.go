package mq

import (
	"context"
	"slices"
	"testing"
)

func TestRoleUsageRetainsRabbitMQAcrossRegionsUntilDeletion(t *testing.T) {
	s, ctx, active := controlFixture(t)
	east := active
	east.ID, east.ARN, east.Engine, east.State = "b-east", "arn:aws:mq:us-east-1:123456789012:broker:east:b-east", "RABBITMQ", "CREATION_IN_PROGRESS"
	west := east
	west.ID, west.ARN, west.Region, west.State = "b-west", "arn:aws:mq:us-west-2:123456789012:broker:west:b-west", "us-west-2", "DELETION_IN_PROGRESS"
	foreign := east
	foreign.AccountID, foreign.ARN = "222222222222", "arn:aws:mq:us-east-1:222222222222:broker:east:b-east"
	partition := east
	partition.Partition, partition.ARN = "aws-cn", "arn:aws-cn:mq:cn-north-1:123456789012:broker:east:b-east"
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		for _, b := range []BrokerRecord{east, west, foreign, partition} {
			if err := tx.PutBroker(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	check := func(want []string) {
		t.Helper()
		err := s.WithMQRoleUsage(ctx, "aws", "123456789012", func(_ context.Context, got []string) error {
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("role dependencies=%v want %v", got, want)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	check([]string{east.ARN, west.ARN})
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteBroker(east.Scope, east.ID) }); err != nil {
		t.Fatal(err)
	}
	check([]string{west.ARN})
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteBroker(west.Scope, west.ID) }); err != nil {
		t.Fatal(err)
	}
	check(nil)
}
