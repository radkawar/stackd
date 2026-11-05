package s3tables

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

// ClaimsData recognizes the reserved namespace even after table deletion.
func (s *Service) ClaimsData(r *http.Request) bool {
	bucket, _ := dataPath(r)
	return strings.HasSuffix(bucket, warehouseBucketSuffix)
}
func dataPath(r *http.Request) (string, string) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(path, "/")
	host := strings.Split(r.Host, ":")[0]
	hostBucket, _, _ := strings.Cut(host, ".")
	if strings.HasSuffix(hostBucket, warehouseBucketSuffix) {
		bucket = hostBucket
		key = strings.TrimPrefix(r.URL.Path, "/")
	}
	return bucket, key
}

// HandleData claims all reserved warehouse paths, including unsupported operations
// and unknown, foreign or deleted tables. A denial must never fall through to S3.
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/developing-s3-tables-APIs.html
// TODO: Comeback publish S3 Tables object/multipart CloudTrail data events;
// control-plane events do not cover this private object transport.
func (s *Service) HandleData(w http.ResponseWriter, r *http.Request) bool {
	bucket, key := dataPath(r)
	if !strings.HasSuffix(bucket, warehouseBucketSuffix) {
		return false
	}
	if err := s.handleData(w, r, bucket, key); err != nil {
		s.dataError(w, r, err)
	}
	return true
}

func (s *Service) handleData(w http.ResponseWriter, r *http.Request, bucket, key string) error {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return invalid("Invalid query encoding")
	}
	for _, values := range q {
		if len(values) != 1 {
			return invalid("Duplicate query parameter")
		}
	}
	op, err := dataOperation(r.Method, key, q)
	if err != nil {
		return err
	}
	action := "PutTableData"
	if op == "read" || op == "list-parts" {
		action = "GetTableData"
	}
	warehouse := "s3://" + bucket
	table, err := s.dataTable(r.Context(), warehouse, action)
	if err != nil {
		return err
	}
	if owner := r.Header.Get("X-Amz-Expected-Bucket-Owner"); owner != "" && owner != table.AccountID {
		return failure("AccessDenied", "The expected bucket owner does not match the table owner", 403)
	}
	if err = validateDataHeaders(r, op); err != nil {
		return err
	}
	location := (&url.URL{Scheme: "s3", Host: bucket, Path: "/" + key}).String()
	switch op {
	case "read":
		if err = requireEmptyDataBody(r); err != nil {
			return err
		}
		if r.Method == http.MethodHead {
			info, err := s.ObjectInfo(r.Context(), location)
			if err != nil {
				return err
			}
			return serveTableObject(w, r, nil, info)
		}
		data, info, err := s.ReadObject(r.Context(), location)
		if err != nil {
			return err
		}
		return serveTableObject(w, r, data, info)
	case "put":
		attrs, err := dataAttributes(r.Header, false)
		if err != nil {
			return err
		}
		data, err := readDataBody(r)
		if err != nil {
			return err
		}
		if rejected := validateChecksums(r.Header, data, false); rejected != nil {
			return rejected
		}
		info, err := s.WriteObject(r.Context(), location, data, attrs, dataConditions(r))
		if err != nil {
			return err
		}
		writeObjectResultHeaders(w, info)
		w.WriteHeader(http.StatusOK)
	case "create":
		if err = requireEmptyDataBody(r); err != nil {
			return err
		}
		attrs, err := dataAttributes(r.Header, true)
		if err != nil {
			return err
		}
		id, err := s.CreateMultipart(r.Context(), location, attrs)
		if err != nil {
			return err
		}
		w.Header().Set("X-Amz-Server-Side-Encryption", "AES256")
		if attrs.ChecksumAlgorithm != "" {
			w.Header().Set("X-Amz-Checksum-Algorithm", attrs.ChecksumAlgorithm)
			w.Header().Set("X-Amz-Checksum-Type", dataMultipartChecksumType(attrs.ChecksumAlgorithm))
		}
		writeXML(w, initiateMultipartResult{XMLNS: dataXMLNamespace, Bucket: bucket, Key: key, UploadID: id})
	case "upload-part":
		number, err := dataInteger(q.Get("partNumber"), 1, 10000)
		if err != nil {
			return invalid("partNumber must be an integer between 1 and 10000")
		}
		data, err := readDataBody(r)
		if err != nil {
			return err
		}
		if rejected := validateChecksums(r.Header, data, false); rejected != nil {
			return rejected
		}
		part, err := s.UploadMultipartPart(r.Context(), location, q.Get("uploadId"), number, data, dataChecksums(r.Header))
		if err != nil {
			return err
		}
		w.Header().Set("ETag", part.ETag)
		w.Header().Set("X-Amz-Server-Side-Encryption", "AES256")
		writeDataChecksums(w.Header(), part.Checksums)
		w.WriteHeader(http.StatusOK)
	case "complete":
		parts, err := decodeCompletedParts(r)
		if err != nil {
			return err
		}
		conditions := dataCompletionConditions(r)
		info, err := s.CompleteMultipart(r.Context(), location, q.Get("uploadId"), parts, conditions, dataChecksums(r.Header))
		if err != nil {
			return err
		}
		writeObjectResultHeaders(w, info)
		writeXML(w, completeMultipartResult{XMLNS: dataXMLNamespace, Location: dataObjectURL(r, bucket, key), Bucket: bucket, Key: key, ETag: info.ETag, ChecksumCRC32: info.Attributes.Checksums.CRC32, ChecksumCRC32C: info.Attributes.Checksums.CRC32C, ChecksumCRC64NVME: info.Attributes.Checksums.CRC64NVME, ChecksumSHA1: info.Attributes.Checksums.SHA1, ChecksumSHA256: info.Attributes.Checksums.SHA256, ChecksumType: dataChecksumType(info.Attributes.Checksums)})
	case "abort":
		if err = requireEmptyDataBody(r); err != nil {
			return err
		}
		if err = s.AbortMultipart(r.Context(), location, q.Get("uploadId")); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
	case "list-parts":
		if err = requireEmptyDataBody(r); err != nil {
			return err
		}
		return s.listMultipartHTTP(w, r, location, bucket, key, q)
	}
	return nil
}

func (s *Service) dataError(w http.ResponseWriter, r *http.Request, err error) {
	// A failed object precondition/range is an XML error, not the object's
	// representation (which may have a non-identity Content-Encoding).
	for _, name := range [...]string{"Content-Type", "Content-Length", "Content-Encoding", "Content-Language", "Content-Disposition", "Cache-Control", "Expires", "X-Amz-Checksum-Crc32", "X-Amz-Checksum-Crc32c", "X-Amz-Checksum-Sha1", "X-Amz-Checksum-Sha256", "X-Amz-Checksum-Type"} {
		w.Header().Del(name)
	}
	e := wireError(err)
	if errors.Is(err, ErrNotFound) {
		e = failure("NoSuchKey", "The table or object does not exist", 404)
	}
	if e.Code == "ForbiddenException" {
		e = failure("AccessDenied", e.Message, 403)
	}
	if e.Code == "BadRequestException" {
		e = failure("InvalidArgument", e.Message, 400)
	}
	model, _ := awscatalog.LookupService("s3")
	awswire.RESTXMLError(w, r, &model, e)
}
func writeXML(w http.ResponseWriter, v any) {
	data, err := xml.Marshal(v)
	if err != nil {
		http.Error(w, "XML encoding failed", 500)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(data)
}
