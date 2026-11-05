package s3tables

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func dataOperation(method, key string, q url.Values) (string, error) {
	op := ""
	switch {
	case q.Has("uploads"):
		if method == http.MethodPost && key != "" && q.Get("uploads") == "" && !q.Has("uploadId") {
			op = "create"
		}
	case q.Has("uploadId"):
		if key == "" || q.Get("uploadId") == "" {
			return "", invalid("An object key and uploadId are required")
		}
		switch method {
		case http.MethodPut:
			op = "upload-part"
		case http.MethodPost:
			op = "complete"
		case http.MethodDelete:
			op = "abort"
		case http.MethodGet:
			op = "list-parts"
		}
	case key != "":
		switch method {
		case http.MethodGet, http.MethodHead:
			op = "read"
		case http.MethodPut:
			op = "put"
		}
	}
	if op == "" {
		return "", failure("NotImplemented", "This object operation is not supported for S3 Tables", 501)
	}
	for name := range q {
		allowed := name == "x-id" || dataSigningQuery(name)
		switch op {
		case "create":
			allowed = allowed || name == "uploads"
		case "upload-part":
			allowed = allowed || name == "uploadId" || name == "partNumber"
		case "complete", "abort":
			allowed = allowed || name == "uploadId"
		case "list-parts":
			allowed = allowed || name == "uploadId" || name == "part-number-marker" || name == "max-parts"
		}
		if !allowed {
			return "", failure("NotImplemented", "This query option is not supported for S3 Tables: "+name, 501)
		}
	}
	return op, nil
}

func dataSigningQuery(name string) bool {
	switch strings.ToLower(name) {
	case "x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-expires", "x-amz-signedheaders", "x-amz-signature", "x-amz-security-token", "x-amz-content-sha256":
		return true
	}
	return false
}

// Only authentication/framing headers are shared across operations. Other
// meaningful S3 options must be implemented or rejected, never silently dropped.
func validateDataHeaders(r *http.Request, op string) error {
	for _, name := range [...]string{"Content-Type", "Content-Encoding", "Content-Length"} {
		if len(r.Header.Values(name)) > 1 {
			return invalid("Duplicate object request header")
		}
	}
	if r.Header.Get("Content-Encoding") != "" && op != "put" && op != "create" {
		return failure("NotImplemented", "Content-Encoding is not supported for this operation", 501)
	}
	for name, values := range r.Header {
		name = strings.ToLower(name)
		meaningful := strings.HasPrefix(name, "x-amz-") || strings.HasPrefix(name, "if-") || name == "range" || name == "content-range" || name == "content-md5" || name == "cache-control" || name == "content-disposition" || name == "content-language" || name == "expires"
		if !meaningful {
			continue
		}
		if len(values) != 1 {
			return invalid("Duplicate object request header")
		}
		allowed := false
		switch name {
		case "x-amz-content-sha256", "x-amz-date", "x-amz-security-token", "x-amz-trailer", "x-amz-decoded-content-length", "x-amz-user-agent", "x-amz-expected-bucket-owner", "x-amz-api-version":
			allowed = true
		case "x-amz-acl", "x-amz-storage-class", "x-amz-server-side-encryption", "cache-control", "content-disposition", "content-language", "expires":
			allowed = op == "put" || op == "create"
		case "x-amz-checksum-algorithm":
			allowed = op == "create"
		case "x-amz-sdk-checksum-algorithm", "content-md5":
			allowed = op == "put" || op == "upload-part"
		case "x-amz-checksum-crc32", "x-amz-checksum-crc32c", "x-amz-checksum-crc64nvme", "x-amz-checksum-sha1", "x-amz-checksum-sha256":
			allowed = op == "put" || op == "upload-part" || op == "complete"
		case "x-amz-checksum-type":
			allowed = op == "create" || op == "complete"
		case "x-amz-mp-object-size":
			return failure("S3TablesUnsupportedHeader", "S3 Tables does not support the x-amz-mp-object-size header", 400)
		case "if-none-match":
			allowed = op == "read" || op == "put" || op == "complete"
		case "if-match":
			allowed = op == "read"
		case "if-modified-since", "if-unmodified-since", "range", "x-amz-checksum-mode":
			allowed = op == "read"
		}
		if name == "x-amz-request-payer" {
			return failure("AccessDenied", "Requester-pays workgroups cannot access S3 Tables data", 403)
		}
		if !allowed {
			return failure("NotImplemented", "This object header is not supported for S3 Tables: "+name, 501)
		}
	}
	if value := r.Header.Get("X-Amz-Checksum-Mode"); value != "" && !strings.EqualFold(value, "ENABLED") {
		return failure("InvalidRequest", "Value for x-amz-checksum-mode header is invalid.", 400)
	}
	if (op == "put" || op == "complete") && r.Header.Get("If-None-Match") != "" && r.Header.Get("If-None-Match") != "*" {
		return invalid("If-None-Match must be '*'")
	}
	return nil
}

func dataAttributes(h http.Header, multipart bool) (ObjectAttributes, error) {
	attrs := ObjectAttributes{ContentType: h.Get("Content-Type"), CacheControl: h.Get("Cache-Control"), ContentDisposition: h.Get("Content-Disposition"), ContentEncoding: h.Get("Content-Encoding"), ContentLanguage: h.Get("Content-Language"), Checksums: dataChecksums(h)}
	if attrs.ContentType == "" {
		attrs.ContentType = "application/octet-stream"
	}
	for _, header := range [...]struct{ name, value string }{{"X-Amz-Acl", "bucket-owner-full-control"}, {"X-Amz-Storage-Class", "STANDARD"}, {"X-Amz-Server-Side-Encryption", "AES256"}} {
		if supplied := h.Get(header.name); supplied != "" && supplied != header.value {
			return ObjectAttributes{}, failure("InvalidRequest", header.name+" is fixed to "+header.value+" for S3 Tables", 400)
		}
	}
	if expires := h.Get("Expires"); expires != "" {
		parsed, err := http.ParseTime(expires)
		if err != nil {
			return ObjectAttributes{}, invalid("Invalid Expires header")
		}
		attrs.Expires = &parsed
	}
	if multipart {
		attrs.ChecksumAlgorithm = h.Get("X-Amz-Checksum-Algorithm")
	} else {
		attrs.ChecksumAlgorithm = h.Get("X-Amz-Sdk-Checksum-Algorithm")
	}
	switch attrs.ChecksumAlgorithm {
	case "", "CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256":
	default:
		return ObjectAttributes{}, failure("NotImplemented", "Unsupported table object checksum algorithm", 501)
	}
	if kind := h.Get("X-Amz-Checksum-Type"); kind != "" {
		if attrs.ChecksumAlgorithm == "CRC64NVME" && kind != "FULL_OBJECT" {
			return ObjectAttributes{}, failure("InvalidRequest", "CRC64NVME requires a full object checksum", 400)
		}
		expected := dataMultipartChecksumType(attrs.ChecksumAlgorithm)
		if kind != expected || expected == "" {
			return ObjectAttributes{}, failure("BadDigest", "The checksum type does not match the checksum algorithm", 400)
		}
	}
	return attrs, nil
}

func dataConditions(r *http.Request) ObjectConditions {
	return ObjectConditions{IfNoneMatch: r.Header.Get("If-None-Match")}
}
func dataChecksums(h http.Header) ObjectChecksums {
	return ObjectChecksums{CRC32: h.Get("X-Amz-Checksum-Crc32"), CRC32C: h.Get("X-Amz-Checksum-Crc32c"), CRC64NVME: h.Get("X-Amz-Checksum-Crc64nvme"), SHA1: h.Get("X-Amz-Checksum-Sha1"), SHA256: h.Get("X-Amz-Checksum-Sha256")}
}
func writeDataChecksums(h http.Header, sums ObjectChecksums) {
	for _, header := range [...]struct{ name, value string }{{"X-Amz-Checksum-Crc32", sums.CRC32}, {"X-Amz-Checksum-Crc32c", sums.CRC32C}, {"X-Amz-Checksum-Crc64nvme", sums.CRC64NVME}, {"X-Amz-Checksum-Sha1", sums.SHA1}, {"X-Amz-Checksum-Sha256", sums.SHA256}} {
		if header.value != "" {
			h.Set(header.name, header.value)
		}
	}
	if kind := dataChecksumType(sums); kind != "" {
		h.Set("X-Amz-Checksum-Type", kind)
	}
}
func dataChecksumType(sums ObjectChecksums) string {
	if sums.CRC64NVME != "" {
		return "FULL_OBJECT"
	}
	for _, value := range []string{sums.CRC32, sums.CRC32C, sums.SHA1, sums.SHA256} {
		if value != "" {
			if strings.Contains(value, "-") {
				return "COMPOSITE"
			}
			return "FULL_OBJECT"
		}
	}
	return ""
}
func dataMultipartChecksumType(algorithm string) string {
	if algorithm == "CRC64NVME" {
		return "FULL_OBJECT"
	}
	if algorithm != "" {
		return "COMPOSITE"
	}
	return ""
}

func dataCompletionConditions(r *http.Request) ObjectConditions {
	conditions := dataConditions(r)
	conditions.ChecksumType = r.Header.Get("X-Amz-Checksum-Type")
	return conditions
}

func writeObjectResultHeaders(w http.ResponseWriter, info ObjectInfo) {
	w.Header().Set("ETag", info.ETag)
	w.Header().Set("X-Amz-Server-Side-Encryption", "AES256")
	writeDataChecksums(w.Header(), info.Attributes.Checksums)
}

func readDataBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		if r.ContentLength > 0 {
			return nil, failure("IncompleteBody", "The request body is shorter than Content-Length", 400)
		}
		return nil, nil
	}
	data, err := io.ReadAll(r.Body)
	if err != nil || (r.ContentLength >= 0 && int64(len(data)) != r.ContentLength) {
		return nil, failure("IncompleteBody", "The request body does not match Content-Length", 400)
	}
	return data, nil
}
func requireEmptyDataBody(r *http.Request) error {
	if r.Body == nil {
		return nil
	}
	var buf [1]byte
	n, err := io.ReadFull(r.Body, buf[:])
	if n != 0 || (err != nil && err != io.EOF) || r.ContentLength > 0 {
		return invalid("This operation does not accept a request body")
	}
	return nil
}
func dataInteger(value string, min, max int) (int, error) {
	if value == "" || strings.IndexFunc(value, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
		return 0, invalid("Invalid integer")
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < min || n > max {
		return 0, invalid("Integer out of range")
	}
	return n, nil
}
