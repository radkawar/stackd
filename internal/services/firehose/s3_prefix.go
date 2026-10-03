package firehose

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/firehose"
	"stackd/internal/awswire"
)

func validateDeliveryConfiguration(destination api.ExtendedS3DestinationDescription) *awswire.Error {
	switch value(destination.CompressionFormat) {
	case "", "UNCOMPRESSED", "GZIP", "ZIP", "Snappy", "HADOOP_SNAPPY":
	default:
		return failure("InvalidArgumentException", "Invalid Firehose compression format.")
	}
	location, err := destinationTimeZone(destination)
	if err != nil {
		return err
	}
	instant := time.Date(8888, 12, 31, 23, 59, 59, 0, location)
	prefix := value(destination.Prefix)
	if _, err := evaluateS3Prefix(prefix, instant, "", true); err != nil {
		return err
	}
	errorPrefix := value(destination.ErrorOutputPrefix)
	if strings.Contains(prefix, "!{") && errorPrefix == "" {
		return failure("InvalidArgumentException", "ErrorOutputPrefix must be specified when Prefix contains expressions.")
	}
	if errorPrefix != "" {
		if strings.Contains(errorPrefix, "!{") && !strings.Contains(errorPrefix, "!{firehose:error-output-type}") {
			return failure("InvalidArgumentException", "ErrorOutputPrefix expressions must include !{firehose:error-output-type}.")
		}
		if _, err := evaluateS3Prefix(errorPrefix, instant, "processing-failed", true); err != nil {
			return err
		}
	}
	return nil
}

func destinationTimeZone(destination api.ExtendedS3DestinationDescription) (*time.Location, *awswire.Error) {
	zone := value(destination.CustomTimeZone)
	if destination.CustomTimeZone == nil || zone == "UTC" {
		return time.UTC, nil
	}
	if !strings.Contains(zone, "/") || strings.HasPrefix(zone, "/") {
		return nil, failure("InvalidArgumentException", "CustomTimeZone must be UTC or an IANA time zone.")
	}
	location, err := time.LoadLocation(zone)
	if err != nil {
		return nil, failure("InvalidArgumentException", "Invalid CustomTimeZone: "+zone)
	}
	return location, nil
}

func s3ObjectKey(stream StreamRecord, buffer BufferRecord) (string, error) {
	location, rejected := destinationTimeZone(stream.Destination)
	if rejected != nil {
		return "", rejected
	}
	instant := buffer.Created.In(location).Truncate(time.Second)
	pattern := value(stream.Destination.Prefix)
	errorType := ""
	switch buffer.Kind {
	case BufferFailed:
		errorType = "processing-failed"
	case BufferDecompressionFailed:
		errorType = "decompression-failed"
	}
	if errorType != "" {
		pattern = value(stream.Destination.ErrorOutputPrefix)
		if pattern == "" {
			pattern = "!{firehose:error-output-type}/"
		}
	}
	prefix, rejected := evaluateS3Prefix(pattern, instant, errorType, false)
	if rejected != nil {
		return "", rejected
	}
	extension := ""
	switch value(stream.Destination.CompressionFormat) {
	case "GZIP":
		extension = ".gz"
	case "ZIP":
		extension = ".zip"
	case "Snappy", "HADOOP_SNAPPY":
		extension = ".snappy"
	}
	if value(stream.Destination.FileExtension) != "" {
		extension = value(stream.Destination.FileExtension)
	}
	return prefix + stream.Key.Name + "-" + strconv.FormatInt(stream.Version, 10) + "-" + instant.Format("2006-01-02-15-04-05") + "-" + uuid.NewString() + extension, nil
}

// Evaluate explicit expressions before appending the implicit timestamp: native
// admission excludes that implicit suffix from the 512-byte prefix limit.
func evaluateS3Prefix(prefix string, instant time.Time, errorType string, validate bool) (string, *awswire.Error) {
	var out strings.Builder
	hasTimestamp := false
	for len(prefix) != 0 {
		start := strings.Index(prefix, "!{")
		if start < 0 {
			out.WriteString(prefix)
			break
		}
		out.WriteString(prefix[:start])
		prefix = prefix[start+2:]
		end := strings.IndexByte(prefix, '}')
		if end < 0 {
			return "", failure("InvalidArgumentException", "Unclosed Firehose S3 prefix expression.")
		}
		expression := prefix[:end]
		prefix = prefix[end+1:]
		switch {
		case strings.HasPrefix(expression, "timestamp:"):
			formatted, err := formatS3Timestamp(strings.TrimPrefix(expression, "timestamp:"), instant)
			if err != nil {
				return "", failure("InvalidArgumentException", err.Error())
			}
			hasTimestamp = true
			out.WriteString(formatted)
		case expression == "firehose:random-string":
			if validate {
				out.WriteString("00000000-00")
			} else {
				out.WriteString(uuid.NewString()[:11])
			}
		case expression == "firehose:error-output-type" && errorType != "":
			out.WriteString(errorType)
		default:
			return "", failure("InvalidArgumentException", "Invalid or unsupported Firehose S3 prefix expression: "+expression)
		}
	}
	if out.Len() > 512 {
		return "", failure("InvalidArgumentException", "The evaluated S3 prefix must not exceed 512 bytes.")
	}
	if !hasTimestamp && errorType == "" {
		out.WriteString(instant.Format("2006/01/02/15/"))
	}
	return out.String(), nil
}
