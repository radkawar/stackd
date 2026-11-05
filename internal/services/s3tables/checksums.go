package s3tables

import (
	"crypto/md5"
	"encoding/base64"
	"net/http"
	"strings"

	"stackd/internal/awschecksum"
	"stackd/internal/awswire"
)

// validateChecksums runs after shared SigV4/aws-chunked verification, over the
// decoded bytes. Never persist frames or acknowledge a corrupt native upload.
func validateChecksums(header http.Header, data []byte, required bool) *awswire.Error {
	found, flexible := false, false
	declared := header.Get("X-Amz-Sdk-Checksum-Algorithm")
	for name, values := range header {
		lower := strings.ToLower(name)
		algorithm := ""
		if lower == "content-md5" {
			algorithm = "MD5"
		} else if strings.HasPrefix(lower, "x-amz-checksum-") && lower != "x-amz-checksum-algorithm" && lower != "x-amz-checksum-type" && lower != "x-amz-checksum-mode" {
			algorithm = strings.ToUpper(strings.TrimPrefix(lower, "x-amz-checksum-"))
			if flexible {
				return failure("InvalidRequest", "Only one payload checksum may be supplied", 400)
			}
			flexible = true
			if declared != "" && declared != algorithm {
				return failure("InvalidRequest", "The checksum algorithm does not match the supplied checksum", 400)
			}
		} else {
			continue
		}
		found = true
		if len(values) != 1 {
			return failure("InvalidRequest", "Duplicate payload checksum", 400)
		}
		decoded, e := base64.StdEncoding.DecodeString(values[0])
		if e != nil || len(decoded) == 0 || (algorithm == "MD5" && len(decoded) != md5.Size) {
			if algorithm == "MD5" {
				return failure("InvalidDigest", "The Content-MD5 you specified is not valid", 400)
			}
			return failure("InvalidRequest", "The checksum provided in your request is not valid", 400)
		}
		sum, e := awschecksum.Sum(algorithm, data)
		if e != nil {
			return failure("NotImplemented", e.Error(), 501)
		}
		if sum != values[0] {
			return failure("BadDigest", "The checksum you specified did not match what we received", 400)
		}
	}
	if declared != "" && !flexible {
		return failure("InvalidRequest", "A checksum value is required with the declared checksum algorithm", 400)
	}
	if required && !found && len(data) > 0 {
		return failure("InvalidRequest", "Missing required Content-MD5 or x-amz-checksum-* header", 400)
	}
	return nil
}
