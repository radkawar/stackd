package s3

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awschecksum"
	"stackd/internal/awswire"
)

func sameMultipartManifest(request api.CompletedPartList, stored []PartRecord) bool {
	if len(request) != len(stored) {
		return false
	}
	for i, part := range request {
		if part.PartNumber == nil || int32(*part.PartNumber) != stored[i].Number || strings.Trim(value(part.ETag), "\"") != strings.Trim(stored[i].ETag, "\"") {
			return false
		}
	}
	return true
}

// assembleMultipart uses retained checksums and ETags, never encrypted payloads.
// Full CRC combination and composite digest construction are distinct contracts.
func assembleMultipart(upload MultipartUploadRecord, stored []PartRecord, in *api.CompleteMultipartUploadInput) (ObjectRecord, []int32, error) {
	record := upload.ObjectRecord
	if record.ChecksumAlgorithm == "" {
		record.ChecksumAlgorithm, record.ChecksumType = "CRC64NVME", "FULL_OBJECT"
	}
	parts := in.MultipartUpload.Parts
	numbers := make([]int32, len(parts))
	etagBytes := make([]byte, 0, len(parts)*md5.Size)
	var checksumBytes []byte
	if record.ChecksumType == "COMPOSITE" {
		checksumBytes = make([]byte, 0, len(parts)*64)
	}
	if in.ChecksumType != nil && value(in.ChecksumType) != record.ChecksumType {
		return record, nil, failure("InvalidRequest", "The complete request must use the checksum mode specified at initiation.", 400)
	}
	var previous int32
	for i, requested := range parts {
		number, wire := multipartPartNumber(requested.PartNumber)
		if wire != nil {
			return record, nil, wire
		}
		if number <= previous {
			wire := failure("InvalidPartOrder", "The list of parts was not in ascending order. Parts must be ordered by part number.", 400)
			wire.UploadID = upload.UploadID
			return record, nil, wire
		}
		previous = number
		numbers[i] = number
	}
	var index int
	for i, requested := range parts {
		number := numbers[i]
		for index < len(stored) && stored[index].Number < number {
			index++
		}
		if index == len(stored) || stored[index].Number != number || strings.Trim(value(requested.ETag), "\"") != strings.Trim(stored[index].ETag, "\"") {
			return record, nil, invalidMultipartPart(upload.UploadID, number, value(requested.ETag))
		}
		part := stored[index]
		if i < len(parts)-1 && part.Size < 5<<20 {
			wire := failure("EntityTooSmall", "Your proposed upload is smaller than the minimum allowed object size.", 400)
			wire.UploadID, wire.ETag, wire.PartNumber = upload.UploadID, strings.Trim(part.ETag, "\""), new(number)
			wire.PartSize, wire.MinSizeAllowed = new(part.Size), new(int64(5<<20))
			return record, nil, wire
		}
		expected := value(requested.ChecksumValue(record.ChecksumAlgorithm))
		if record.ChecksumType == "COMPOSITE" && expected == "" {
			return record, nil, failure("InvalidRequest", "The checksum is missing for a part in the completion request.", 400)
		}
		for algorithm, checksum := range requested.Checksums {
			if upload.ChecksumAlgorithm != algorithm || checksum != part.Checksum {
				return record, nil, invalidMultipartPart(upload.UploadID, number, value(requested.ETag))
			}
		}
		if record.ChecksumType == "COMPOSITE" && number != int32(i+1) {
			return record, nil, failure("InternalError", "We encountered an internal error. Please try again.", 500)
		}
		var err error
		etagBytes, err = hex.AppendDecode(etagBytes, []byte(strings.Trim(part.ETag, "\"")))
		if err != nil {
			return record, nil, err
		}
		if record.ChecksumType == "COMPOSITE" {
			checksumBytes, err = base64.StdEncoding.AppendDecode(checksumBytes, []byte(part.Checksum))
		} else if i == 0 {
			record.Checksum = part.Checksum
		} else {
			record.Checksum, err = awschecksum.CombineCRC(record.ChecksumAlgorithm, record.Checksum, part.Checksum, part.Size)
		}
		if err != nil {
			return record, nil, err
		}
		record.Size += part.Size
	}
	suffix := "-" + strconv.Itoa(len(parts))
	etag := md5.Sum(etagBytes)
	record.ETag = "\"" + hex.EncodeToString(etag[:]) + suffix + "\""
	if record.ChecksumType == "COMPOSITE" {
		sum, err := awschecksum.Sum(record.ChecksumAlgorithm, checksumBytes)
		if err != nil {
			return record, nil, err
		}
		record.Checksum = sum + suffix
	}
	if in.MpuObjectSize != nil && int64(*in.MpuObjectSize) != record.Size {
		return record, nil, failure("InvalidRequest", "The specified multipart object size does not match the uploaded object size.", 400)
	}
	for algorithm, checksum := range in.Checksums {
		if upload.ChecksumAlgorithm == "" {
			// Legacy completion headers are ignored without explicit initiation.
			// Newer families require their algorithm to have been selected then.
			switch algorithm {
			case "CRC32", "CRC32C", "SHA1", "SHA256":
				continue
			case "MD5", "SHA512", "XXHASH64", "XXHASH3", "XXHASH128":
				return record, nil, failure("InvalidRequest", "The checksum algorithm must be specified when initiating the upload.", 400)
			}
		}
		if algorithm != record.ChecksumAlgorithm || checksum != record.Checksum {
			return record, nil, failure("BadDigest", "The checksum you specified did not match what we received.", 400)
		}
	}
	return record, numbers, nil
}

func invalidMultipartPart(uploadID string, number int32, etag string) *awswire.Error {
	wire := failure("InvalidPart", "One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.", 400)
	wire.UploadID, wire.PartNumber, wire.ETag = uploadID, new(number), strings.Trim(etag, "\"")
	return wire
}
