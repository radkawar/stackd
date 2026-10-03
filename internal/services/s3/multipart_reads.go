package s3

import (
	"errors"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func objectChecksumType(record ObjectRecord) string {
	if record.ChecksumType != "" {
		return record.ChecksumType
	}
	return "FULL_OBJECT"
}

// selectRange uses completed-selection ordinals, not original upload numbers.
// Native controls reader-gap/subset and read-list part-number-reads distinguish
// those ordinals, ordinary objects, and the 200 response for an empty MPU part.
func (read *objectRead) selectRange(tx Reader, in *api.GetObjectInput) error {
	record := read.object
	start, end, wire := awswire.ByteRange(value(in.Range), record.Size)
	if wire != nil {
		return wire
	}
	read.start, read.end = start, end
	read.contentRange = (in.Range != nil || in.PartNumber != nil) && record.Size != 0
	checksums := value(in.ChecksumMode) == "ENABLED"
	composite := objectChecksumType(record) == "COMPOSITE"
	var parts []PartRecord
	if record.UploadID != "" && (in.PartNumber != nil || (checksums && composite && in.Range != nil && (start != 0 || end != record.Size))) {
		var err error
		parts, err = tx.ObjectParts(record.VersionKey())
		if err != nil {
			return err
		}
		if len(parts) == 0 {
			return errors.New("completed multipart object has no parts")
		}
	}
	if in.PartNumber != nil {
		count := int32(1)
		if record.UploadID != "" {
			count = int32(len(parts))
			read.partsCount = new(api.PartsCount(count))
		}
		number := int32(*in.PartNumber)
		if number > count {
			return &awswire.Error{Code: "InvalidPartNumber", Message: "The requested partnumber is not satisfiable", StatusCode: 416,
				S3ErrorDetails: awswire.S3ErrorDetails{PartNumberRequested: new(number), ActualPartCount: new(count)}}
		}
		if len(parts) != 0 {
			read.start = 0
			for _, part := range parts[:number-1] {
				read.start += part.Size
			}
			part := parts[number-1]
			read.end = read.start + part.Size
			if checksums && composite {
				read.checksum = part.Checksum
				return nil
			}
		}
	}
	if !checksums {
		return nil
	}
	// A whole-object range retains the object checksum; an exact composite
	// part range exposes the part digest without the object's -N suffix.
	// Full-object checksum algorithms never expose a partial-object digest.
	if read.start == 0 && read.end == record.Size {
		read.checksum = record.Checksum
		return nil
	}
	if composite {
		var offset int64
		for _, part := range parts {
			if offset == read.start && offset+part.Size == read.end {
				read.checksum = part.Checksum
				break
			}
			offset += part.Size
		}
	}
	return nil
}
