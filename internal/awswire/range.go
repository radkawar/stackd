package awswire

import (
	"strconv"
	"strings"
)

// ByteRange returns the half-open range accepted by S3 object and deployment
// archive downloads. Multiple ranges are not supported by S3.
func ByteRange(spec string, size int64) (int64, int64, *Error) {
	if spec == "" {
		return 0, size, nil
	}
	bad := &Error{Code: "InvalidRange", Message: "The requested range is not satisfiable.", StatusCode: 416}
	if !strings.HasPrefix(spec, "bytes=") || strings.Contains(spec, ",") {
		return 0, 0, bad
	}
	start, end, ok := strings.Cut(strings.TrimPrefix(spec, "bytes="), "-")
	if !ok || size == 0 {
		return 0, 0, bad
	}
	if start == "" {
		n, err := strconv.ParseInt(end, 10, 64)
		if err != nil || n <= 0 {
			return 0, 0, bad
		}
		return max(0, size-n), size, nil
	}
	first, err := strconv.ParseInt(start, 10, 64)
	if err != nil || first < 0 || first >= size {
		return 0, 0, bad
	}
	if end == "" {
		return first, size, nil
	}
	last, err := strconv.ParseInt(end, 10, 64)
	if err != nil || last < first {
		return 0, 0, bad
	}
	if last >= size-1 {
		return first, size, nil
	}
	return first, last + 1, nil
}
