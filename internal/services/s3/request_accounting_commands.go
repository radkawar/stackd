package s3

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/google/uuid"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Internal commands share the source snapshot with HTTP accounting. The public
// observer owns actual transport bytes; internal commands do not invent them.
func (s *Service) captureRequestCommand(reader Reader, c *apiCall, bucket BucketRecord) {
	s.captureRequest(reader, bucket, c.accessPoint)
	if c.accountingCaptured {
		return
	}
	c.accountingCaptured = true
	if observed, ok := reader.Context().Value(requestObservationKey{}).(*requestObservation); ok && observed.action == c.name {
		c.requestMetrics = observed.metrics
		return
	}
	if c.accessLogOperation != "BATCH.DELETE.OBJECT" {
		var pointARN string
		if c.accessPoint != nil {
			pointARN = c.accessPoint.Key.ARN()
		}
		version, _ := c.params["versionId"].(string)
		metrics, err := s.captureRequestMetrics(reader, bucket, c.name, c.key, version, pointARN, c.copySource, s.clock.Now())
		if err != nil {
			slog.Warn("S3 internal request metric configuration lookup failed", "bucket", bucket.Key.Name, "error", err)
		} else {
			c.requestMetrics = metrics
		}
	}
	config, err := reader.BucketLogging(bucket.Key)
	if err != nil {
		slog.Warn("S3 internal access log configuration lookup failed", "bucket", bucket.Key.Name, "error", err)
		return
	}
	if config != nil {
		c.accessLog = &AccessLogDelivery{Source: bucket.Key, AccountID: bucket.AccountID, Region: bucket.Region, Destination: *config, At: s.clock.Now()}
	}
}

func (s *Service) recordRequestCommand(ctx context.Context, c *apiCall, wire *awswire.Error) error {
	if observed, ok := ctx.Value(requestObservationKey{}).(*requestObservation); ok && observed.action == c.name {
		observed.call = c
	} else if err := s.publishInternalMetrics(ctx, c, wire); err != nil {
		return err
	}
	if c.accessLog == nil {
		return nil
	}
	m := awsctx.FromContext(ctx)
	model, _ := awscatalog.LookupService("s3")
	operation, _ := model.Operation(c.name)
	record := accessLogRecord{
		owner: canonicalID(m.Partition, c.account), bucket: c.bucket, at: c.accessLog.At,
		requester: accessLogRequester(m), requestID: m.RequestID,
		operation: accessLogOperation(c.name), key: c.key, status: operation.HTTPStatus,
		objectSize: -1, totalMillis: -1, turnaroundMillis: -1,
		aclRequired: c.aclRequired,
	}
	if c.accessPoint != nil {
		record.accessPoint = c.accessPoint.Key.ARN()
	}
	if c.accessLogOperation != "" {
		record.operation = c.accessLogOperation
	}
	if wire != nil {
		record.status, record.errorCode = wire.StatusCode, wire.Code
	}
	if size, ok := c.additional["objectSize"].(int64); ok {
		record.objectSize = size
	}
	copyRead := m.InvokedBy == "AWS Internal" && c.name == "GetObject"
	batchDelete := record.operation == "BATCH.DELETE.OBJECT"
	if copyRead || batchDelete {
		if observed, ok := ctx.Value(requestObservationKey{}).(*requestObservation); ok {
			m.RequestID = awsctx.FromContext(observed.request.Context()).RequestID
			record.captureTransport(observed.request, m)
			record.hostID = awswire.S3HostID(m.RequestID)
			if copyRead {
				record.hostID, _ = c.additional["x-amz-id-2"].(string)
			}
		}
		if copyRead && wire != nil {
			// Copy auditing encodes rejected source keys before completion.
			record.key, _ = url.QueryUnescape(c.key)
		}
	}
	if version, ok := c.params["versionId"].(string); ok && !copyRead && !batchDelete {
		record.versionID = version
	}
	delivery := *c.accessLog
	delivery.ID, delivery.Due = uuid.NewString(), s.clock.Now().Add(accessLogInterval)
	delivery.Record = record.format()
	// Join the source commit. The shared scheduler's recovery poll discovers
	// committed work; do not signal external delivery from inside a transaction.
	return s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutAccessLogDelivery(delivery)
	})
}
