package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type kinesisJobs struct{ s *Service }

func (j kinesisJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(r Reader) error {
		ds, e := r.KinesisDestinations()
		if e != nil {
			return e
		}
		for _, d := range ds {
			if !d.Due.IsZero() && (!found || d.Due.Before(job.Due)) {
				job = scheduler.Job{Key: "destination:" + d.ID, Due: d.Due}
				found = true
			}
		}
		id, due, e := r.NextKinesisDelivery()
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if !found || due.Before(job.Due) {
			job = scheduler.Job{Key: "delivery:" + id, Due: due}
			found = true
		}
		return nil
	})
	return
}
func (j kinesisJobs) Run(ctx context.Context, job scheduler.Job) error {
	if strings.HasPrefix(job.Key, "destination:") {
		return j.s.advanceKinesisDestination(ctx, strings.TrimPrefix(job.Key, "destination:"))
	}
	return j.s.deliverKinesis(ctx, strings.TrimPrefix(job.Key, "delivery:"))
}
func (s *Service) advanceKinesisDestination(ctx context.Context, id string) error {
	var d KinesisDestination
	found := false
	if err := s.repository.View(ctx, func(r Reader) error {
		ds, e := r.KinesisDestinations()
		if e != nil {
			return e
		}
		for _, v := range ds {
			if v.ID == id {
				d = v
				found = true
				break
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if !found || d.Due.IsZero() || d.Due.After(s.clock.Now()) {
		return nil
	}
	original := d
	switch d.Status {
	case "ENABLING":
		message := d.AdmissionFailure
		parsed, err := arn.Parse(d.StreamARN)
		switch {
		case err != nil || parsed.Service != "kinesis" || parsed.Partition != d.Table.Partition || parsed.AccountID != d.Table.AccountID || !strings.HasPrefix(parsed.Resource, "stream/"):
			message = "The kinesis Arn used to enable kinesis replication belongs to a stream which is not in Active state"
		case parsed.Region != d.Table.Region:
			message = "The kinesis Arn used to enable kinesis replication belongs to a stream which is not in the current region"
		case message == "":
			identity, e := s.kinesisContext(ctx, d.Table, "")
			if e != nil {
				message = e.Error()
			} else {
				out, rejected := s.kinesis.DescribeStream(identity, &api.DescribeStreamInput{StreamARN: new(api.StreamARN(d.StreamARN)), Limit: new(api.DescribeStreamInputLimit(1))})
				if rejected != nil {
					message = "User does not have a permission to use kinesis stream"
				} else if out == nil || out.StreamDescription == nil || value(out.StreamDescription.StreamStatus) != "ACTIVE" {
					message = "The kinesis Arn used to enable kinesis replication belongs to a stream which is not in Active state"
				}
			}
		}
		d.Status = "ACTIVE"
		d.Description = ""
		if message != "" {
			d.Status = "ENABLE_FAILED"
			d.Description = message
		}
		d.Due = time.Time{}
	case "UPDATING":
		d.Precision = d.PendingPrecision
		d.PendingPrecision = ""
		d.Status = "ACTIVE"
		d.Due = time.Time{}
	case "DISABLING":
		d.Status = "DISABLED"
		d.Due = d.CaptureUntil
	case "DISABLED":
		d.CaptureUntil = time.Time{}
		d.Due = time.Time{}
	default:
		d.Due = time.Time{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		ds, err := tx.KinesisDestinations()
		if err != nil {
			return err
		}
		for _, current := range ds {
			if current.ID == id {
				if current != original {
					return nil
				}
				return tx.PutKinesisDestination(d)
			}
		}
		return nil
	})
}
func (s *Service) kinesisContext(ctx context.Context, table TableKey, parent string) (context.Context, error) {
	if s.kinesisIdentity == nil || s.kinesis == nil {
		return nil, errors.New("DynamoDB Kinesis delivery is not configured")
	}
	m := awsctx.FromContext(ctx)
	m.Partition = table.Partition
	m.AccountID = table.AccountID
	m.Region = table.Region
	m.ParentEventID = parent
	return s.kinesisIdentity.Context(awsctx.WithMetadata(ctx, m), table)
}
func (s *Service) deliverKinesis(ctx context.Context, id string) error {
	var d KinesisDelivery
	err := s.repository.View(ctx, func(r Reader) error { var err error; d, err = r.KinesisDelivery(id); return err })
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if d.Due.After(s.clock.Now()) {
		return nil
	}
	identity, deliveryErr := s.kinesisContext(ctx, d.Table, d.ParentEventID)
	if deliveryErr == nil {
		out, rejected := s.kinesis.PutRecords(identity, &api.PutRecordsInput{StreamARN: new(api.StreamARN(d.StreamARN)), Records: api.PutRecordsRequestEntryList{{Data: api.Data(d.Data), PartitionKey: new(api.PartitionKey(d.PartitionKey))}}})
		if rejected != nil {
			deliveryErr = rejected
		} else if out == nil || len(out.Records) != 1 {
			deliveryErr = errors.New("kinesis returned no record result")
		} else if value(out.Records[0].ErrorCode) != "" {
			deliveryErr = fmt.Errorf("%s: %s", value(out.Records[0].ErrorCode), value(out.Records[0].ErrorMessage))
		} else if value(out.Records[0].SequenceNumber) == "" {
			deliveryErr = errors.New("kinesis did not confirm record publication")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		if deliveryErr == nil {
			return tx.DeleteKinesisDelivery(d.ID)
		}
		d.Attempts++
		d.LastError = deliveryErr.Error()
		d.Due = s.clock.Now().Add(time.Second * time.Duration(1<<min(d.Attempts, 6)))
		return tx.PutKinesisDelivery(d)
	})
}

// Role deletion and subscription membership share the store transaction. Retried
// records continue to use the role after their subscription stops capturing.
func (s *Service) WithKinesisRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []TableKey) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		ds, err := tx.KinesisDestinations()
		if err != nil {
			return err
		}
		deliveries, err := tx.KinesisDeliveries()
		if err != nil {
			return err
		}
		seen := map[TableKey]bool{}
		var tables []TableKey
		add := func(k TableKey) {
			if k.Partition == partition && k.AccountID == account && !seen[k] {
				seen[k] = true
				tables = append(tables, k)
			}
		}
		for _, d := range ds {
			if d.Status == "ACTIVE" || d.Status == "ENABLING" || d.Status == "UPDATING" || d.Status == "DISABLING" || d.CaptureUntil.After(s.clock.Now()) {
				add(d.Table)
			}
		}
		for _, d := range deliveries {
			add(d.Table)
		}
		return fn(tx.Context(), tables)
	})
}
