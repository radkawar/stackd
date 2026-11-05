package s3tables

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func serveTableObject(w http.ResponseWriter, r *http.Request, data []byte, info ObjectInfo) error {
	h := w.Header()
	h.Set("ETag", info.ETag)
	h.Set("Accept-Ranges", "bytes")
	h.Set("X-Amz-Server-Side-Encryption", "AES256")
	modified := info.Modified.UTC().Truncate(time.Second)
	if !info.Modified.IsZero() {
		h.Set("Last-Modified", modified.Format(http.TimeFormat))
	}
	attrs := info.Attributes
	for _, header := range [...]struct{ name, value string }{{"Content-Type", attrs.ContentType}, {"Cache-Control", attrs.CacheControl}, {"Content-Disposition", attrs.ContentDisposition}, {"Content-Encoding", attrs.ContentEncoding}, {"Content-Language", attrs.ContentLanguage}} {
		if header.value != "" {
			h.Set(header.name, header.value)
		}
	}
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", "application/octet-stream")
	}
	if attrs.Expires != nil {
		h.Set("Expires", attrs.Expires.UTC().Format(http.TimeFormat))
	}
	if strings.EqualFold(r.Header.Get("X-Amz-Checksum-Mode"), "ENABLED") {
		writeDataChecksums(h, attrs.Checksums)
	}
	// S3 gives entity-tag conditions precedence over their date counterpart.
	if match := r.Header.Get("If-Match"); match != "" {
		if !dataETagMatches(match, info.ETag, false) {
			return failure("PreconditionFailed", "At least one precondition failed", 412)
		}
	} else if value, err := http.ParseTime(r.Header.Get("If-Unmodified-Since")); err == nil && modified.After(value) {
		return failure("PreconditionFailed", "At least one precondition failed", 412)
	}
	if match := r.Header.Get("If-None-Match"); match != "" {
		if dataETagMatches(match, info.ETag, true) {
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
	} else if value, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil && !modified.After(value) {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	start, end, status := int64(0), info.Size, http.StatusOK
	if value := r.Header.Get("Range"); value != "" {
		var err error
		start, end, err = dataByteRange(value, info.Size)
		if err != nil {
			h.Set("Content-Range", "bytes */"+strconv.FormatInt(info.Size, 10))
			return err
		}
		status = http.StatusPartialContent
		h.Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end-1, 10)+"/"+strconv.FormatInt(info.Size, 10))
	}
	h.Set("Content-Length", strconv.FormatInt(end-start, 10))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data[start:end])
	}
	return nil
}

func dataETagMatches(value, etag string, weak bool) bool {
	for _, candidate := range strings.Split(value, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		if weak {
			candidate = strings.TrimPrefix(candidate, "W/")
		}
		if candidate == etag {
			return true
		}
	}
	return false
}

// S3 supports one byte range per request, unlike net/http.ServeContent, which
// generates multipart/byteranges responses for multiple ranges.
func dataByteRange(value string, size int64) (int64, int64, error) {
	invalidRange := failure("InvalidRange", "The requested range is not satisfiable", 416)
	if !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") || size == 0 {
		return 0, 0, invalidRange
	}
	first, last, ok := strings.Cut(strings.TrimPrefix(value, "bytes="), "-")
	if !ok || (first == "" && last == "") {
		return 0, 0, invalidRange
	}
	parse := func(value string) (int64, error) {
		if strings.IndexFunc(value, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			return 0, invalidRange
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, invalidRange
		}
		return n, nil
	}
	if first == "" {
		n, err := parse(last)
		if err != nil || n == 0 {
			return 0, 0, invalidRange
		}
		if n > size {
			n = size
		}
		return size - n, size, nil
	}
	start, err := parse(first)
	if err != nil || start >= size {
		return 0, 0, invalidRange
	}
	end := size
	if last != "" {
		n, err := parse(last)
		if err != nil || n < start {
			return 0, 0, invalidRange
		}
		if n < size-1 {
			end = n + 1
		}
	}
	return start, end, nil
}
