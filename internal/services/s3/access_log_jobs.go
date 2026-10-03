package s3

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// AWS promises best-effort delivery, not a fixed delay or retry duration. These
// are local service-time scheduling and retention bounds, not AWS latency claims.
const accessLogInterval = 5 * time.Minute
const accessLogRetention = 24 * time.Hour

func (s *Service) enqueueAccessLog(ctx context.Context, delivery AccessLogDelivery) error {
	delivery.ID = uuid.NewString()
	delivery.Due = s.clock.Now().Add(accessLogInterval)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutAccessLogDelivery(delivery)
	}); err != nil {
		return err
	}
	s.jobs.Wake()
	return nil
}

type accessLogDeliveries struct{ service *Service }

func (source accessLogDeliveries) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := source.service.repository.View(ctx, func(r Reader) error {
		var err error
		job, found, err = r.NextAccessLogDelivery()
		return err
	})
	return job, found, err
}

func (source accessLogDeliveries) Run(ctx context.Context, job scheduler.Job) error {
	s := source.service
	var delivery AccessLogDelivery
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		delivery, err = r.AccessLogDelivery(job.Key)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	now := s.clock.Now()
	if delivery.Due.After(now) {
		return nil
	}
	var rejected *awswire.Error
	if now.Before(delivery.At.Add(accessLogRetention)) {
		metadata := awsctx.Metadata{Partition: delivery.Source.Partition, AccountID: delivery.AccountID,
			Region: delivery.Region, RequestID: strings.ReplaceAll(uuid.NewString(), "-", "")}
		destinationCtx := awsctx.WithMetadata(ctx, metadata)
		destinationCtx = awsctx.WithServicePrincipal(destinationCtx, awsctx.ServicePrincipal{
			Name: "logging.s3.amazonaws.com", SourceARN: delivery.Source.ARN(), Type: "Service",
		})
		_, rejected = s.putObject(destinationCtx, &api.PutObjectInput{
			Bucket:              new(api.BucketName(delivery.Destination.TargetBucket)),
			Key:                 new(api.ObjectKey(accessLogObjectKey(delivery, now))),
			ExpectedBucketOwner: new(api.AccountId(delivery.AccountID)),
			Body:                []byte(delivery.Record), ContentType: new(api.ContentType("text/plain")),
		}, &delivery)
		if rejected != nil {
			slog.WarnContext(ctx, "S3 access log delivery rejected", "source", delivery.Source.Name,
				"destination", delivery.Destination.TargetBucket, "code", rejected.Code, "error", rejected.Message)
		}
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		if rejected == nil {
			return tx.DeleteAccessLogDelivery(delivery.ID)
		}
		delivery.Due = now.Add(accessLogInterval)
		return tx.PutAccessLogDelivery(delivery)
	})
}

func accessLogObjectKey(delivery AccessLogDelivery, now time.Time) string {
	instant := now.UTC()
	prefix := delivery.Destination.TargetPrefix
	switch delivery.Destination.KeyFormat {
	case "PartitionedPrefix", "EventTime", "DeliveryTime":
		if delivery.Destination.KeyFormat != "DeliveryTime" {
			instant = delivery.At.UTC().Truncate(24 * time.Hour)
		}
		prefix += delivery.AccountID + "/" + delivery.Region + "/" + delivery.Source.Name + "/" + instant.Format("2006/01/02/")
	}
	unique := strings.ToUpper(strings.ReplaceAll(delivery.ID, "-", "")[:16])
	return prefix + instant.Format("2006-01-02-15-04-05") + "-" + unique
}

func accessLogDestination(bucket BucketRecord, delivery *AccessLogDelivery) error {
	if bucket.AccountID != delivery.AccountID || bucket.Region != delivery.Region || bucket.RequesterPays {
		return denied()
	}
	if bucket.EncryptionAlgorithm != "" && bucket.EncryptionAlgorithm != "AES256" {
		return failure("InvalidRequest", "Server access logging requires an SSE-S3 destination.", 400)
	}
	return nil
}
