package s3

import (
	"encoding/base64"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awschecksum"
	"stackd/internal/awswire"
)

type checksumInput interface {
	Checksums(func(string, string) bool)
}

// suppliedChecksum owns selection and syntax for payload checksum headers. The
// generated view preserves present-empty fields; they are not absent checksums.
func suppliedChecksum(in checksumInput, declared *api.ChecksumAlgorithm) (string, string, *awswire.Error) {
	var algorithm, expected string
	for name, checksum := range in.Checksums {
		if algorithm != "" || (declared != nil && value(declared) != name) {
			return "", "", failure("InvalidRequest", "The checksum algorithm does not match the supplied checksum.", 400)
		}
		if decoded, err := base64.StdEncoding.DecodeString(checksum); err != nil || len(decoded) == 0 {
			return "", "", failure("InvalidRequest", "The checksum provided in your request is not valid.", 400)
		}
		algorithm, expected = name, checksum
	}
	if declared != nil && algorithm == "" {
		return "", "", failure("InvalidRequest", "A checksum value is required with ChecksumAlgorithm.", 400)
	}
	return algorithm, expected, nil
}

func putChecksum(in *api.PutObjectInput, required bool) (string, string, *awswire.Error) {
	algorithm, expected, wire := suppliedChecksum(in, in.ChecksumAlgorithm)
	if wire != nil {
		return "", "", wire
	}
	if required && expected == "" && value(in.ContentMD5) == "" {
		return "", "", failure("InvalidRequest", "Content-MD5 OR x-amz-checksum- HTTP header is required for Put Object requests with Object Lock parameters", 400)
	}
	if algorithm == "" {
		algorithm = "CRC64NVME"
	}
	sum, err := awschecksum.Sum(algorithm, in.Body)
	if err != nil {
		return "", "", unsupported(err.Error())
	}
	if expected != "" && expected != sum {
		return "", "", failure("BadDigest", "The checksum you specified did not match what we received.", 400)
	}
	return algorithm, sum, nil
}

// The transport checksum does not change the checksum chosen at initiation.
// Unconfigured uploads retain CRC64NVME for completion, but expose a part
// checksum only when one was supplied on this request.
func uploadPartChecksum(in *api.UploadPartInput, upload MultipartUploadRecord) (algorithm, sum, stored string, wire *awswire.Error) {
	algorithm, expected, wire := suppliedChecksum(in, in.ChecksumAlgorithm)
	if wire != nil {
		return "", "", "", wire
	}
	if expected == "" && upload.ChecksumType == "COMPOSITE" {
		return "", "", "", failure("InvalidRequest", "The checksum required for this part is missing.", 400)
	}
	if expected == "" && value(in.ContentMD5) == "" && (upload.Retention.Mode != "" || upload.LegalHold != "") {
		return "", "", "", failure("InvalidRequest", "Content-MD5 OR x-amz-checksum- HTTP header is required for Put Part requests with Object Lock parameters", 400)
	}
	if algorithm != "" && upload.ChecksumAlgorithm != "" && algorithm != upload.ChecksumAlgorithm {
		return "", "", "", failure("InvalidRequest", "The checksum algorithm does not match the checksum algorithm specified at initiation.", 400)
	}
	storageAlgorithm := upload.ChecksumAlgorithm
	if storageAlgorithm == "" {
		storageAlgorithm = "CRC64NVME"
	}
	if algorithm != "" {
		var err error
		sum, err = awschecksum.Sum(algorithm, in.Body)
		if err != nil {
			return "", "", "", unsupported(err.Error())
		}
		if sum != expected {
			return "", "", "", failure("BadDigest", "The checksum you specified did not match what we received.", 400)
		}
	}
	stored = sum
	if algorithm != storageAlgorithm {
		var err error
		stored, err = awschecksum.Sum(storageAlgorithm, in.Body)
		if err != nil {
			return "", "", "", unsupported(err.Error())
		}
	}
	// Explicit full-object uploads return the server-calculated part checksum
	// even when its transport header was omitted.
	if algorithm == "" && upload.ChecksumAlgorithm != "" {
		algorithm, sum = storageAlgorithm, stored
	}
	return algorithm, sum, stored, nil
}
