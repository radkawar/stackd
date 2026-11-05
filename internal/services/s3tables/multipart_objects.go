package s3tables

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awschecksum"
)

const (
	MultipartMinimumPartSize int64 = 5 * 1024 * 1024
	MultipartMaximumPartSize int64 = 5 * 1024 * 1024 * 1024
	MultipartMaximumParts          = 10000
)

func checksumValue(c ObjectChecksums, algorithm string) string {
	switch algorithm {
	case "CRC32":
		return c.CRC32
	case "CRC32C":
		return c.CRC32C
	case "CRC64NVME":
		return c.CRC64NVME
	case "SHA1":
		return c.SHA1
	case "SHA256":
		return c.SHA256
	}
	return ""
}
func checksumSet(c *ObjectChecksums, algorithm, value string) {
	switch algorithm {
	case "CRC32":
		c.CRC32 = value
	case "CRC32C":
		c.CRC32C = value
	case "CRC64NVME":
		c.CRC64NVME = value
	case "SHA1":
		c.SHA1 = value
	case "SHA256":
		c.SHA256 = value
	}
}

var tableChecksumAlgorithms = [...]string{"CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"}

func checksumAlgorithm(c ObjectChecksums) (string, error) {
	out := ""
	for _, algorithm := range tableChecksumAlgorithms {
		if checksumValue(c, algorithm) == "" {
			continue
		}
		if out != "" {
			return "", failure("InvalidRequest", "Only one payload checksum may be supplied", 400)
		}
		out = algorithm
	}
	return out, nil
}
func validateObjectAttributes(attrs ObjectAttributes) error {
	switch attrs.ChecksumAlgorithm {
	case "", "CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256":
		return nil
	default:
		return failure("NotImplemented", "The checksum algorithm is not supported for S3 Tables", 501)
	}
}
func validateObjectChecksums(c ObjectChecksums, data []byte) error {
	if c == (ObjectChecksums{}) {
		return nil
	}
	h := make(http.Header)
	for _, algorithm := range tableChecksumAlgorithms {
		if value := checksumValue(c, algorithm); value != "" {
			h.Set("X-Amz-Checksum-"+algorithm, value)
		}
	}
	if err := validateChecksums(h, data, false); err != nil {
		return err
	}
	return nil
}

// CloneObjectInfo prevents callers from changing a stored Expires timestamp.
func CloneObjectInfo(info ObjectInfo) ObjectInfo {
	info.Attributes = CloneObjectAttributes(info.Attributes)
	return info
}
func CloneObjectAttributes(attrs ObjectAttributes) ObjectAttributes {
	if attrs.Expires != nil {
		v := attrs.Expires.UTC()
		attrs.Expires = &v
	}
	return attrs
}
func SingleObjectInfo(key string, data []byte, attrs ObjectAttributes, modified time.Time) (ObjectInfo, error) {
	if err := validateObjectAttributes(attrs); err != nil {
		return ObjectInfo{}, err
	}
	if err := validateObjectChecksums(attrs.Checksums, data); err != nil {
		return ObjectInfo{}, err
	}
	algorithm, err := checksumAlgorithm(attrs.Checksums)
	if err != nil {
		return ObjectInfo{}, err
	}
	if attrs.ChecksumAlgorithm != "" && attrs.ChecksumAlgorithm != algorithm {
		return ObjectInfo{}, failure("InvalidRequest", "A matching checksum value is required with the declared checksum algorithm", 400)
	}
	attrs.ChecksumAlgorithm = algorithm
	if attrs.ContentType == "" {
		attrs.ContentType = "application/octet-stream"
	}
	sum := md5.Sum(data)
	return ObjectInfo{Key: key, ETag: "\"" + hex.EncodeToString(sum[:]) + "\"", Size: int64(len(data)), Modified: modified.UTC(), Attributes: CloneObjectAttributes(attrs)}, nil
}
func NoSuchMultipartUpload() error {
	return failure("NoSuchUpload", "The specified multipart upload does not exist", 404)
}

// CheckObjectConditions is shared by both physical stores inside the publication
// transaction. Final S3 Tables objects are write-once, even without an explicit
// If-None-Match header and even when the proposed bytes are identical.
func CheckObjectConditions(exists bool, c ObjectConditions) error {
	if c.IfNoneMatch != "" && c.IfNoneMatch != "*" {
		return failure("InvalidArgument", "If-None-Match must be *", 400)
	}
	if exists {
		return failure("PreconditionFailed", "At least one precondition failed", 412)
	}
	return nil
}

func ValidateMultipartCompletionParts(parts []CompletedPart) error {
	if len(parts) == 0 || len(parts) > MultipartMaximumParts {
		return failure("InvalidRequest", "The completion must contain between 1 and 10000 parts", 400)
	}
	previous := 0
	for _, part := range parts {
		if part.Number < 1 || part.Number > MultipartMaximumParts {
			return failure("InvalidPart", "Invalid part number", 400)
		}
		if part.Number <= previous {
			return failure("InvalidPartOrder", "Parts must be in ascending order", 400)
		}
		previous = part.Number
	}
	return nil
}

// CheckMultipartCompletionConditions runs inside physical publication transactions.
// CRC64NVME is always a full-object checksum, never a composite digest.
func CheckMultipartCompletionConditions(info ObjectInfo, conditions ObjectConditions) error {
	if info.Attributes.ChecksumAlgorithm == "CRC64NVME" && conditions.ChecksumType != "" && conditions.ChecksumType != "FULL_OBJECT" {
		return failure("InvalidRequest", "CRC64NVME requires a full object checksum", 400)
	}
	checksumType := ""
	if info.Attributes.ChecksumAlgorithm == "CRC64NVME" {
		checksumType = "FULL_OBJECT"
	} else if info.Attributes.ChecksumAlgorithm != "" {
		checksumType = "COMPOSITE"
	}
	if conditions.ChecksumType != "" && conditions.ChecksumType != checksumType {
		return failure("BadDigest", "The checksum type does not match the multipart upload", 400)
	}
	return nil
}

// MultipartObjectInfo validates exact selected plaintext part records and derives
// metadata without copying their bytes. Stores own atomic encrypted publication.
// AWS: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html
func MultipartObjectInfo(upload MultipartUpload, stored map[int]StoredMultipartPart, selected []CompletedPart, modified time.Time, supplied ObjectChecksums) (ObjectInfo, error) {
	if err := ValidateMultipartCompletionParts(selected); err != nil {
		return ObjectInfo{}, err
	}
	if _, err := checksumAlgorithm(supplied); err != nil {
		return ObjectInfo{}, err
	}
	algorithm := upload.Attributes.ChecksumAlgorithm
	if err := validateObjectAttributes(upload.Attributes); err != nil {
		return ObjectInfo{}, err
	}
	if algorithm == "" {
		if supplied.CRC64NVME != "" {
			algorithm = "CRC64NVME"
		} else {
			for _, requested := range selected {
				if requested.Checksums.CRC64NVME != "" || stored[requested.Number].Checksums.CRC64NVME != "" {
					algorithm = "CRC64NVME"
					break
				}
			}
		}
	}
	var total int64
	etagHash := md5.New()
	var checksumBytes []byte
	digestSize := 0
	fullChecksum := ""
	switch algorithm {
	case "CRC32", "CRC32C":
		digestSize = 4
	case "SHA1":
		digestSize = 20
	case "SHA256":
		digestSize = 32
	}
	if digestSize != 0 {
		checksumBytes = make([]byte, 0, len(selected)*digestSize)
	}
	for i, requested := range selected {
		part, exists := stored[requested.Number]
		if !exists || requested.ETag == "" || strings.Trim(requested.ETag, "\"") != strings.Trim(part.ETag, "\"") {
			return ObjectInfo{}, failure("InvalidPart", "The part or its ETag does not match the uploaded part", 400)
		}
		if part.Size != int64(len(part.Data)) || part.Size > MultipartMaximumPartSize {
			return ObjectInfo{}, failure("InvalidPart", "Invalid stored part size", 400)
		}
		if i != len(selected)-1 && part.Size < MultipartMinimumPartSize {
			return ObjectInfo{}, failure("EntityTooSmall", "Each part except the last must be at least 5 MiB", 400)
		}
		partSum := md5.Sum(part.Data)
		if "\""+hex.EncodeToString(partSum[:])+"\"" != part.ETag {
			return ObjectInfo{}, failure("InvalidPart", "Stored part does not match its ETag", 400)
		}
		_, _ = etagHash.Write(partSum[:])
		requestedAlgorithm, err := checksumAlgorithm(requested.Checksums)
		if err != nil {
			return ObjectInfo{}, err
		}
		if algorithm == "CRC64NVME" {
			if requestedAlgorithm != "" && requestedAlgorithm != algorithm {
				return ObjectInfo{}, failure("InvalidPart", "The part checksum algorithm does not match the multipart upload", 400)
			}
			actual, err := awschecksum.Sum(algorithm, part.Data)
			if err != nil {
				return ObjectInfo{}, err
			}
			if part.Checksums.CRC64NVME != "" {
				if part.Checksums != (ObjectChecksums{CRC64NVME: actual}) {
					return ObjectInfo{}, failure("BadDigest", "The stored part checksum does not match its bytes", 400)
				}
			} else if err := validateObjectChecksums(part.Checksums, part.Data); err != nil {
				return ObjectInfo{}, err
			}
			if requested.Checksums.CRC64NVME != "" && requested.Checksums.CRC64NVME != actual {
				return ObjectInfo{}, failure("InvalidPart", "The part checksum does not match the uploaded part", 400)
			}
			if i == 0 {
				fullChecksum = actual
			} else {
				fullChecksum, err = awschecksum.CombineCRC(algorithm, fullChecksum, actual, part.Size)
				if err != nil {
					return ObjectInfo{}, err
				}
			}
		} else if algorithm != "" {
			if requested.Number != i+1 {
				return ObjectInfo{}, failure("InvalidPartOrder", "Checksummed part numbers must be consecutive and begin with 1", 400)
			}
			if requestedAlgorithm != algorithm || checksumValue(requested.Checksums, algorithm) != checksumValue(part.Checksums, algorithm) {
				return ObjectInfo{}, failure("InvalidPart", "The part checksum does not match the uploaded part", 400)
			}
			if err := validateObjectChecksums(part.Checksums, part.Data); err != nil {
				return ObjectInfo{}, err
			}
			checksumBytes, err = base64.StdEncoding.AppendDecode(checksumBytes, []byte(checksumValue(part.Checksums, algorithm)))
			if err != nil {
				return ObjectInfo{}, failure("InvalidPart", "Invalid part checksum", 400)
			}
		} else if requestedAlgorithm != "" && checksumValue(requested.Checksums, requestedAlgorithm) != checksumValue(part.Checksums, requestedAlgorithm) {
			return ObjectInfo{}, failure("InvalidPart", "The part checksum does not match the uploaded part", 400)
		}
		total += part.Size
	}
	if total > int64(int(^uint(0)>>1)) {
		return ObjectInfo{}, failure("EntityTooLarge", "The object exceeds addressable storage", 400)
	}
	attrs := CloneObjectAttributes(upload.Attributes)
	attrs.ChecksumAlgorithm = algorithm
	attrs.Checksums = ObjectChecksums{}
	if algorithm == "CRC64NVME" {
		attrs.Checksums.CRC64NVME = fullChecksum
		if supplied != (ObjectChecksums{}) && supplied != attrs.Checksums {
			return ObjectInfo{}, failure("BadDigest", "The object checksum does not match the full object checksum", 400)
		}
	} else if algorithm != "" {
		composite, err := awschecksum.Sum(algorithm, checksumBytes)
		if err != nil {
			return ObjectInfo{}, err
		}
		composite += "-" + strconv.Itoa(len(selected))
		checksumSet(&attrs.Checksums, algorithm, composite)
		if supplied != (ObjectChecksums{}) && supplied != attrs.Checksums {
			return ObjectInfo{}, failure("BadDigest", "The object checksum does not match the multipart checksum", 400)
		}
	}
	// Preserve legacy completion-only checksum semantics for non-CRC64 uploads
	// that did not select an algorithm at initiation.
	if attrs.ContentType == "" {
		attrs.ContentType = "application/octet-stream"
	}
	var sumBuffer [md5.Size]byte
	sum := etagHash.Sum(sumBuffer[:0])
	info := ObjectInfo{Key: upload.Key, ETag: "\"" + hex.EncodeToString(sum[:]) + "-" + strconv.Itoa(len(selected)) + "\"", Size: total, Modified: modified.UTC(), Attributes: attrs}
	return info, nil
}
