package s3

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type inventoryReports struct{ service *Service }

type inventoryReportKey struct {
	Bucket            BucketKey
	ID, ParentEventID string
}

func (source inventoryReports) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := source.service.repository.View(ctx, func(r Reader) error {
		bucket, configuration, err := r.NextInventoryConfiguration()
		if err != nil || configuration == nil {
			return err
		}
		key, err := json.Marshal(inventoryReportKey{Bucket: bucket, ID: configuration.ID, ParentEventID: configuration.ParentEventID})
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: string(key), Due: configuration.NextReport}, true
		return nil
	})
	return job, found, err
}

func (source inventoryReports) Run(ctx context.Context, job scheduler.Job) error {
	var key inventoryReportKey
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	s := source.service
	var bucket BucketRecord
	var configuration *InventoryConfiguration
	var columns []inventoryColumn
	var rows [][]any
	var destination BucketRecord
	var destinationError error
	err := s.repository.View(ctx, func(r Reader) error {
		current, err := r.BucketInventoryConfiguration(key.Bucket, key.ID)
		if err != nil {
			return err
		}
		if current == nil || !current.Enabled || current.ParentEventID != key.ParentEventID || !current.NextReport.Equal(job.Due) {
			return nil
		}
		configuration = current
		bucket, err = r.Bucket(key.Bucket)
		if err != nil {
			return err
		}
		target, _ := arn.Parse(configuration.Destination.BucketARN) // syntax was admitted by the configuration command
		destination, destinationError = r.Bucket(BucketKey{Partition: target.Partition, Name: target.Resource})
		if destinationError != nil {
			if errors.Is(destinationError, ErrNotFound) {
				return nil
			}
			return destinationError
		}
		if destination.Key.Partition != bucket.Key.Partition || destination.Region != bucket.Region {
			destinationError = errors.New("inventory source and destination must be in the same partition and Region")
			return nil
		}
		if expected := configuration.Destination.AccountID; expected != nil && *expected != destination.AccountID {
			destinationError = errors.New("inventory destination account does not match its configured owner")
			return nil
		}
		columns = inventoryColumns(*configuration)
		rows, err = inventoryRows(r, bucket, *configuration, job.Due, columns)
		return err
	})
	if err != nil || configuration == nil {
		return err
	}
	if destinationError == nil {
		destinationError = s.deliverInventory(ctx, bucket, destination, *configuration, job.Due, columns, rows)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if destinationError != nil {
		slog.WarnContext(ctx, "S3 inventory report delivery failed", "source", bucket.Key.Name, "configuration", key.ID,
			"destination", configuration.Destination.BucketARN, "scheduled", job.Due, "error", destinationError)
	}
	// Reports are periodic, not an exactly-once export. Failed destinations are
	// attempted again at the next occurrence; no undocumented retry ledger is
	// introduced. Interrupted executions leave this occurrence eligible.
	next := job.Due.Add(24 * time.Hour)
	if configuration.Weekly {
		for next.Weekday() != time.Sunday {
			next = next.Add(24 * time.Hour)
		}
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		return tx.AdvanceInventoryReport(key.Bucket, key.ID, key.ParentEventID, job.Due, next)
	})
}

type inventoryManifest struct {
	SourceBucket      string                  `json:"sourceBucket"`
	DestinationBucket string                  `json:"destinationBucket"`
	Version           string                  `json:"version"`
	CreationTimestamp string                  `json:"creationTimestamp"`
	FileFormat        string                  `json:"fileFormat"`
	FileSchema        string                  `json:"fileSchema"`
	Files             []inventoryManifestFile `json:"files"`
}

type inventoryManifestFile struct {
	Key         string `json:"key"`
	Size        int64  `json:"size"`
	MD5Checksum string `json:"MD5checksum"`
}

func (s *Service) deliverInventory(ctx context.Context, source, destination BucketRecord, configuration InventoryConfiguration, at time.Time, columns []inventoryColumn, rows [][]any) error {
	data, schema, extension, err := encodeInventory(ctx, configuration.Destination.Format, columns, rows, s.inventoryORC)
	if err != nil {
		return err
	}
	prefix := value(configuration.Destination.Prefix)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	prefix += source.Key.Name + "/" + configuration.ID + "/"
	// The accepted revision and occurrence identify a retry's ordinary report
	// object. This is an object name, not a second publication/receipt protocol.
	fileID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(configuration.ParentEventID+"/"+at.Format(time.RFC3339Nano))).String()
	dataKey := prefix + "data/" + fileID + "." + extension
	dataChecksum := md5.Sum(data)
	manifest, err := json.Marshal(inventoryManifest{
		SourceBucket: source.Key.Name, DestinationBucket: configuration.Destination.BucketARN,
		Version: "2016-11-30", CreationTimestamp: strconv.FormatInt(at.UnixMilli(), 10),
		FileFormat: configuration.Destination.Format, FileSchema: schema,
		Files: []inventoryManifestFile{{Key: dataKey, Size: int64(len(data)), MD5Checksum: hex.EncodeToString(dataChecksum[:])}},
	})
	if err != nil {
		return err
	}
	manifestPrefix := prefix + at.UTC().Format("2006-01-02T15-04Z") + "/"
	checksum := md5.Sum(manifest)
	files := []struct {
		key, contentType string
		body             []byte
	}{
		{dataKey, "application/octet-stream", data},
		{manifestPrefix + "manifest.json", "application/json", manifest},
		{prefix + "hive/dt=" + at.UTC().Format("2006-01-02-15-04") + "/symlink.txt", "text/plain", []byte("s3://" + destination.Key.Name + "/" + dataKey + "\n")},
		// AWS documents checksum creation as the completed-report notification.
		// Every referenced data/discovery object must exist before this write.
		{manifestPrefix + "manifest.checksum", "text/plain", []byte(hex.EncodeToString(checksum[:]))},
	}
	for _, file := range files {
		metadata := awsctx.Metadata{Partition: source.Key.Partition, AccountID: source.AccountID, Region: source.Region,
			ParentEventID: configuration.ParentEventID, RequestID: strings.ReplaceAll(uuid.NewString(), "-", "")}
		owned := awsctx.WithServicePrincipal(awsctx.WithMetadata(ctx, metadata), awsctx.ServicePrincipal{
			Name: "s3.amazonaws.com", SourceARN: source.Key.ARN(), Type: "Service",
		})
		input := &api.PutObjectInput{
			Bucket: new(api.BucketName(destination.Key.Name)), Key: new(api.ObjectKey(file.key)), Body: file.body,
			ContentType: new(api.ContentType(file.contentType)), ACL: new(api.ObjectCannedACL("bucket-owner-full-control")),
			ExpectedBucketOwner: new(api.AccountId(destination.AccountID)),
		}
		if configuration.Destination.Encryption != "" {
			input.ServerSideEncryption = new(api.ServerSideEncryption(configuration.Destination.Encryption))
		}
		if configuration.Destination.KMSKeyID != "" {
			input.SSEKMSKeyId = new(api.SSEKMSKeyId(configuration.Destination.KMSKeyID))
		}
		if _, wire := s.PutObject(owned, input); wire != nil {
			return fmt.Errorf("write inventory object %s: %w", file.key, wire)
		}
	}
	return nil
}
