package s3tables_test

import (
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AWS C++ 1.11.900, used by real PyArrow, signs this S3 protocol-version
// header. It is request framing, not an unimplemented object storage option.
func TestTableDataHEADAcceptsAWSCPPAPIVersionHeader(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "cpp_framing")
	path := "/" + strings.TrimPrefix(string(*table.MetadataLocation), "s3://")
	request := httptest.NewRequest(http.MethodHead, path, nil).WithContext(f.ctx)
	request.Header.Set("X-Amz-Api-Version", "2006-03-01")
	response := httptest.NewRecorder()
	if !f.service.HandleData(response, request) || response.Code != http.StatusOK {
		t.Fatalf("AWS C++ protocol header was rejected: %d %s", response.Code, response.Body.String())
	}
	if response.Body.Len() != 0 || response.Header().Get("Content-Length") == "" || response.Header().Get("ETag") == "" {
		t.Fatalf("HEAD framing lost object metadata or returned payload: %#v %s", response.Header(), response.Body.String())
	}
}

// The retained native S3 capture accepts both cases; real PyArrow uses lowercase.
// See testdata/aws/s3/checksum_mode_case_20261103.json.
func TestTableDataChecksumModeCasePreservesVerifiedChecksum(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "checksum_mode")
	path := "/" + strings.TrimPrefix(string(*table.WarehouseLocation), "s3://") + "/data/checksum"
	payload := "actual checksum-mode object bytes"
	sum := crc32.ChecksumIEEE([]byte(payload))
	expected := base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32(nil, sum))
	put := httptest.NewRequest(http.MethodPut, path, strings.NewReader(payload)).WithContext(f.ctx)
	put.Header.Set("X-Amz-Checksum-Crc32", expected)
	written := httptest.NewRecorder()
	f.service.HandleData(written, put)
	if written.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", written.Code, written.Body.String())
	}
	for _, mode := range []string{"enabled", "ENABLED"} {
		request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(f.ctx)
		request.Header.Set("X-Amz-Checksum-Mode", mode)
		response := httptest.NewRecorder()
		f.service.HandleData(response, request)
		if response.Code != http.StatusOK || response.Body.String() != payload || response.Header().Get("X-Amz-Checksum-Crc32") != expected {
			t.Fatalf("%s: %d %#v %s", mode, response.Code, response.Header(), response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(f.ctx)
	request.Header.Set("X-Amz-Checksum-Mode", "invalid")
	response := httptest.NewRecorder()
	f.service.HandleData(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "<Code>InvalidRequest</Code>") {
		t.Fatalf("invalid mode: %d %s", response.Code, response.Body.String())
	}
}
