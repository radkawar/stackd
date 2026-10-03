package integrations

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudwatch"
	"stackd/internal/services/mq"
	"stackd/storage/memory"
)

type mqInterruptedMetrics struct {
	owner     *cloudwatch.Service
	calls     int
	interrupt bool
}

func (p *mqInterruptedMetrics) Publish(ctx context.Context, namespace string, data []api.MetricDatum) error {
	p.calls++
	if err := p.owner.Publish(ctx, namespace, data); err != nil {
		return err
	}
	if p.interrupt && p.calls == 2 {
		return errors.New("interrupted second native metric batch")
	}
	return nil
}

func TestMQMetricsBatchRollbackAndFilteredTotals(t *testing.T) {
	domain := memory.NewDomain()
	repository := cloudwatch.NewMemoryRepository(domain)
	brokers := mq.NewMemoryRepository(domain)
	now := time.Date(2035, 1, 2, 3, 4, 0, 0, time.UTC)
	owner := cloudwatch.New(cloudwatch.Config{Repository: repository, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = owner.Close() })
	publisher := &mqInterruptedMetrics{owner: owner, interrupt: true}
	adapter := MQMetrics{Metrics: publisher}
	broker := mq.BrokerRecord{Scope: mq.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "measured-broker", Engine: "RABBITMQ", EngineVersion: "3.13.7"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws-cn", AccountID: "999999999999", Region: "cn-north-1"})
	sample := mq.MetricSnapshot{RabbitMQ: &mq.RabbitMQMetrics{}}
	for i := range 250 {
		sample.RabbitMQ.Queues = append(sample.RabbitMQ.Queues, mq.QueueMetrics{Name: fmt.Sprintf("queue-%03d", i), VirtualHost: "/", Ready: int64(i % 4), Unacknowledged: 1, Consumers: 2})
	}
	sample.RabbitMQ.Queues = append(sample.RabbitMQ.Queues, mq.QueueMetrics{Name: "not published", VirtualHost: "/", Ready: 11, Unacknowledged: 3, Consumers: 1})
	publish := func() error {
		return brokers.Update(ctx, func(tx mq.Transaction) error { return adapter.PublishMQMetrics(tx.Context(), broker, sample, now) })
	}
	if err := publish(); err == nil {
		t.Fatal("interrupted publication succeeded")
	}
	scope := cloudwatch.Scope{Partition: broker.Partition, AccountID: broker.AccountID, Region: broker.Region}
	if err := repository.View(ctx, func(r cloudwatch.Reader) error {
		rows, err := r.Metrics(cloudwatch.MetricQuery{Scope: scope, Namespace: "AWS/AmazonMQ", Limit: 2000})
		if err == nil && len(rows) != 0 {
			t.Fatalf("partial metric batches escaped rollback: %d identities", len(rows))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	publisher.interrupt = false
	if err := publish(); err != nil {
		t.Fatal(err)
	}
	expected := map[string]float64{"QueueCount": 251, "MessageCount": 637, "MessageReadyCount": 384, "MessageUnacknowledgedCount": 253, "ConsumerCount": 501}
	if err := repository.View(ctx, func(r cloudwatch.Reader) error {
		rows, err := r.Metrics(cloudwatch.MetricQuery{Scope: scope, Namespace: "AWS/AmazonMQ", Limit: 2000})
		if err != nil {
			return err
		}
		for _, row := range rows {
			for _, dimension := range row.Dimensions {
				if dimension.Name == "Queue" && dimension.Value == "not published" {
					t.Fatal("unsupported queue name published")
				}
			}
			if len(row.Dimensions) != 1 {
				continue
			}
			if row.Dimensions[0] != (cloudwatch.Dimension{Name: "Broker", Value: broker.Name}) {
				t.Fatalf("wrong broker dimensions: %+v", row.Dimensions)
			}
			want, ok := expected[row.Key.Name]
			if !ok {
				continue
			}
			points := 0
			if err := r.Points(cloudwatch.PointQuery{MetricID: row.ID, Start: now.Unix(), End: now.Add(time.Minute).Unix()}, func(p cloudwatch.Point) error {
				points++
				if p.Sum != want || p.Minimum != want || p.Maximum != want || p.SampleCount != 1 || p.Unit != "Count" {
					t.Fatalf("%s sample=%+v, want Count %v exactly once", row.Key.Name, p, want)
				}
				return nil
			}); err != nil {
				return err
			}
			if points != 1 {
				t.Fatalf("%s points=%d, want 1", row.Key.Name, points)
			}
			delete(expected, row.Key.Name)
		}
		if len(expected) != 0 {
			t.Fatalf("missing broker gauges: %v", expected)
		}
		foreign, err := r.Metrics(cloudwatch.MetricQuery{Scope: cloudwatch.Scope{Partition: "aws-cn", AccountID: "999999999999", Region: "cn-north-1"}, Limit: 2000})
		if err == nil && len(foreign) != 0 {
			t.Fatal("metrics leaked into incoming caller scope")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMQInactiveDurableSubscriberMetricCeiling(t *testing.T) {
	domain := memory.NewDomain()
	repository := cloudwatch.NewMemoryRepository(domain)
	now := time.Date(2035, 1, 2, 3, 4, 0, 0, time.UTC)
	owner := cloudwatch.New(cloudwatch.Config{Repository: repository, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = owner.Close() })
	adapter := MQMetrics{Metrics: owner}
	broker := mq.BrokerRecord{Scope: mq.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "durable-owner", Engine: "ACTIVEMQ"}
	expected := make(map[int64]float64)
	for i, sample := range []struct {
		native    int64
		published float64
	}{
		{1999, 1999}, {2000, 2000}, {2001, 2000}, {3000, 2000}, {0, 0},
	} {
		at := now.Add(time.Duration(i) * time.Minute)
		snapshot := mq.MetricSnapshot{ActiveMQ: &mq.ActiveMQMetrics{InactiveDurableTopicSubscribers: sample.native}}
		if err := adapter.PublishMQMetrics(t.Context(), broker, snapshot, at); err != nil {
			t.Fatal(err)
		}
		expected[at.Unix()] = sample.published
	}
	err := repository.View(t.Context(), func(r cloudwatch.Reader) error {
		rows, err := r.Metrics(cloudwatch.MetricQuery{
			Scope:     cloudwatch.Scope{Partition: broker.Partition, AccountID: broker.AccountID, Region: broker.Region},
			Namespace: "AWS/AmazonMQ", Name: "InactiveDurableTopicSubscribersCount", Limit: 10,
		})
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			t.Fatalf("inactive subscriber identities = %d, want one", len(rows))
		}
		if len(rows[0].Dimensions) != 1 || rows[0].Dimensions[0] != (cloudwatch.Dimension{Name: "Broker", Value: broker.Name + "-1"}) {
			t.Fatalf("wrong inactive subscriber dimensions: %+v", rows[0].Dimensions)
		}
		return r.Points(cloudwatch.PointQuery{MetricID: rows[0].ID, Start: now.Unix(), End: now.Add(5 * time.Minute).Unix()}, func(p cloudwatch.Point) error {
			want, ok := expected[p.Timestamp]
			if !ok || p.Sum != want || p.Minimum != want || p.Maximum != want || p.SampleCount != 1 || p.Unit != "Count" {
				t.Fatalf("inactive subscriber sample = %+v, want %v (expected timestamp: %v)", p, want, ok)
			}
			delete(expected, p.Timestamp)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != 0 {
		t.Fatalf("missing inactive subscriber samples: %v", expected)
	}
}
