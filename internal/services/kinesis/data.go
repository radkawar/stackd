package kinesis

import (
	"context"
	"regexp"
	"unicode/utf8"

	api "stackd/internal/awsapi/kinesis"
)

const maxDataBytes = 10 << 20

var decimalCoordinate = regexp.MustCompile(`^[0-9]{1,129}$`)

func registerData(s *Service) {
	registerOperation(s, "PutRecord", s.PutRecord)
	registerOperation(s, "PutRecords", s.PutRecords)
	registerOperation(s, "GetShardIterator", s.GetShardIterator)
	registerOperation(s, "GetRecords", s.GetRecords)
}

func dryRunResult(action string) error {
	return failure("DryRunOperationException", "DryRunOperation validation succeeded while calling "+action+" operation.: Request would have succeeded, but DryRun flag is set.")
}

func isDryRun(v *api.BooleanObject) bool { return v != nil && bool(*v) }

// Generated HTTP binding checks model constraints before dispatch. These cheap
// checks preserve the same boundary for the exported typed commands as well.
func validateRecord(data api.Data, key *api.PartitionKey, explicit *api.HashKey) error {
	if data == nil {
		return failure("ValidationException", "Data must not be null.")
	}
	if key == nil || utf8.RuneCountInString(value(key)) < 1 || utf8.RuneCountInString(value(key)) > 256 {
		return failure("ValidationException", "PartitionKey must contain between 1 and 256 characters.")
	}
	if len(data) > maxDataBytes {
		return failure("ValidationException", "Data must not exceed 10485760 bytes.")
	}
	if explicit != nil {
		if !decimalCoordinate.MatchString(value(explicit)) {
			return failure("ValidationException", "ExplicitHashKey must be a decimal integer.")
		}
		if _, err := partitionHash(value(key), explicit); err != nil {
			return err
		}
	}
	return nil
}

func validateRecordSize(stream StreamRecord, data api.Data, key string) error {
	maximum := 1024 << 10
	if stream.Data.MaxRecordSizeInKiB != nil {
		maximum = int(*stream.Data.MaxRecordSizeInKiB) << 10
	}
	if len(data)+len(key) > maximum {
		return failure("InvalidArgumentException", "Record size exceeds the stream's maximum record size.")
	}
	return nil
}

// Dry-run admission deliberately avoids opening the log and ordinary routing or
// position checks. Authorization still precedes resource existence checks.
func (s *Service) dryRunStream(ctx context.Context, name, arn, action string) (StreamRecord, error) {
	var stream StreamRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		stream, err = s.stream(r.Context(), r, name, arn, action)
		if err != nil {
			return err
		}
		return requireReadable(stream)
	})
	if err == nil {
		rememberStream(ctx, stream)
	}
	return stream, err
}
