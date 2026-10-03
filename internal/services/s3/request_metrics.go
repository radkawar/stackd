package s3

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	metricsapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Request samples retain their original time and individual values. CloudWatch
// owns persistence, minute aggregation, percentiles and alarm evaluation; S3
// does not maintain a competing metric ledger or promise native delivery lag.
type requestMetricsObservation struct {
	bucket            BucketRecord
	configurations    []RequestMetricsConfiguration
	key, category     string
	at, started       time.Time
	tags, replacement []Tag
	replaced          bool
}

func requestMetricCategory(action, key string) string {
	switch action {
	case "ListObjects", "ListObjectsV2", "ListObjectVersions", "ListMultipartUploads", "ListParts":
		return "ListRequests"
	case "DeleteObjects":
		return "DeleteRequests"
	case "SelectObjectContent":
		return "SelectRequests"
	}
	if key == "" {
		return ""
	}
	model, _ := awscatalog.LookupService("s3")
	operation, ok := model.Operation(action)
	if !ok {
		return ""
	}
	switch operation.HTTPMethod {
	case http.MethodGet:
		return "GetRequests"
	case http.MethodPut:
		return "PutRequests"
	case http.MethodPost:
		return "PostRequests"
	case http.MethodDelete:
		return "DeleteRequests"
	case http.MethodHead:
		return "HeadRequests"
	default:
		return ""
	}
}

func (s *Service) captureRequestMetrics(reader Reader, bucket BucketRecord, action, key, version, accessPoint string, copySource bool, at time.Time) (*requestMetricsObservation, error) {
	category := requestMetricCategory(action, key)
	if s.metrics == nil || category == "" {
		return nil, nil
	}
	configurations, err := reader.BucketMetricsConfigurations(BucketConfigurationQuery{Bucket: bucket.Key, Limit: maxMetricsConfigurations})
	if err != nil {
		return nil, err
	}
	selected := configurations[:0]
	needTags := false
	for _, configuration := range configurations {
		if filter := configuration.Filter; filter != nil {
			// Even an access-point filter excludes bucket-content lists and
			// multi-object deletes. ListParts identifies one upload key.
			if key == "" || filter.Prefix != nil && !strings.HasPrefix(key, *filter.Prefix) || filter.AccessPointARN != "" && filter.AccessPointARN != accessPoint {
				continue
			}
			if len(filter.Tags) != 0 {
				// A copy's internal GET and uncompleted upload parts have no
				// object-tag population, even when their source/upload is tagged.
				if copySource || action == "UploadPart" || action == "UploadPartCopy" || action == "ListParts" || action == "AbortMultipartUpload" || action == "CompleteMultipartUpload" {
					continue
				}
				needTags = true
			}
		}
		selected = append(selected, configuration)
	}
	if len(selected) == 0 {
		return nil, nil
	}
	observation := &requestMetricsObservation{bucket: bucket, configurations: selected, key: key, category: category, at: at, started: time.Now()}
	if !needTags {
		return observation, nil
	}
	objectKey := ObjectKey{Bucket: bucket.Key, Name: key}
	var object ObjectRecord
	if version == "" {
		object, err = reader.Object(objectKey)
	} else {
		object, err = reader.ObjectVersion(ObjectVersionKey{ObjectKey: objectKey, VersionID: version})
	}
	if errors.Is(err, ErrNotFound) {
		return observation, nil
	}
	if err != nil {
		return nil, err
	}
	if !object.DeleteMarker {
		observation.tags, err = reader.ObjectTags(object.VersionKey())
	}
	return observation, err
}

// Record the admitted replacement, not a post-write readback. Failed commands
// still select their original tags; successful creates/tag changes use new tags.
func (c *apiCall) requestMetricTags(tags []Tag) {
	if c.requestMetrics != nil {
		c.requestMetrics.replacement, c.requestMetrics.replaced = tags, true
	}
}

func requestMetricFirstByte(action string) bool {
	switch action {
	case "GetObject", "GetObjectAttributes", "GetObjectTagging", "PutObject", "CopyObject", "UploadPart", "UploadPartCopy",
		"CreateMultipartUpload", "CompleteMultipartUpload", "AbortMultipartUpload", "ListObjects", "ListObjectsV2", "ListObjectVersions", "ListMultipartUploads", "ListParts":
		return true
	default:
		return false
	}
}

func (s *Service) publishHTTPMetrics(ctx context.Context, o *requestObservation, elapsed time.Duration) error {
	if o.metrics == nil {
		return nil
	}
	status := o.writer.status
	if status == 0 {
		status = http.StatusOK
	}
	success := status >= 200 && status < 300 && o.writer.errorCode == ""
	var firstByte *time.Duration
	if success && requestMetricFirstByte(o.action) && !o.received.IsZero() && !o.firstByte.IsZero() {
		firstByte = new(o.firstByte.Sub(o.received))
	}
	bytesIn, bytesOut := o.bytesRead, o.writer.bytes
	if o.action == "DeleteObjects" {
		// Native multi-delete counts one DELETE but has no byte population.
		bytesIn, bytesOut = 0, 0
	}
	return s.publishRequestMetrics(ctx, o.metrics, status, success, bytesIn, bytesOut, firstByte, &elapsed)
}

func (s *Service) publishInternalMetrics(ctx context.Context, c *apiCall, wire *awswire.Error) error {
	if c.requestMetrics == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("s3")
	operation, _ := model.Operation(c.name)
	status := operation.HTTPStatus
	if wire != nil {
		status = wire.StatusCode
	}
	var firstByte *time.Duration
	if wire == nil && requestMetricFirstByte(c.name) {
		firstByte = new(time.Since(c.requestMetrics.started))
	}
	// Internal copy/replication reads count, but are not network transfers.
	return s.publishRequestMetrics(ctx, c.requestMetrics, status, wire == nil, 0, 0, firstByte, nil)
}

func (s *Service) publishRequestMetrics(ctx context.Context, observation *requestMetricsObservation, status int, success bool, bytesIn, bytesOut int64, firstByte, total *time.Duration) error {
	tags := observation.tags
	if success && observation.replaced {
		tags = observation.replacement
	}
	observation.configurations = slices.DeleteFunc(observation.configurations, func(configuration RequestMetricsConfiguration) bool {
		filter := configuration.Filter
		return filter != nil && !objectFilterMatches(filter.ObjectFilter, ObjectRecord{Key: ObjectKey{Name: observation.key}}, tags)
	})
	if len(observation.configurations) == 0 {
		return nil
	}
	at := metricsapi.Timestamp(observation.at)
	samples := make([]metricsapi.MetricDatum, 0, 8)
	add := func(name, unit string, value float64) {
		samples = append(samples, metricsapi.MetricDatum{MetricName: new(metricsapi.MetricName(name)), Unit: new(metricsapi.StandardUnit(unit)), Timestamp: &at, Value: new(metricsapi.DatapointValue(value))})
	}
	add("AllRequests", "Count", 1)
	add(observation.category, "Count", 1)
	clientError, serverError := float64(0), float64(0)
	if status >= 400 && status < 500 {
		clientError = 1
	}
	if status >= 500 {
		serverError = 1
	}
	add("4xxErrors", "Count", clientError)
	add("5xxErrors", "Count", serverError)
	if bytesIn > 0 {
		add("BytesUploaded", "Bytes", float64(bytesIn))
	}
	if bytesOut > 0 {
		add("BytesDownloaded", "Bytes", float64(bytesOut))
	}
	if firstByte != nil {
		add("FirstByteLatency", "Milliseconds", float64(*firstByte)/float64(time.Millisecond))
	}
	if total != nil {
		add("TotalRequestLatency", "Milliseconds", float64(*total)/float64(time.Millisecond))
	}
	data := make([]metricsapi.MetricDatum, 0, len(observation.configurations)*len(samples))
	for _, configuration := range observation.configurations {
		dimensions := metricsapi.Dimensions{
			{Name: new(metricsapi.DimensionName("BucketName")), Value: new(metricsapi.DimensionValue(observation.bucket.Key.Name))},
			{Name: new(metricsapi.DimensionName("FilterId")), Value: new(metricsapi.DimensionValue(configuration.ID))},
		}
		for _, sample := range samples {
			sample.Dimensions = dimensions
			data = append(data, sample)
		}
	}
	m := awsctx.Metadata{Partition: observation.bucket.Key.Partition, AccountID: observation.bucket.AccountID, Region: observation.bucket.Region, InvokedBy: "s3.amazonaws.com"}
	return s.metrics.Publish(awsctx.WithMetadata(ctx, m), "AWS/S3", data)
}
