package s3tables_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"stackd/internal/authorization"
	"stackd/internal/awschecksum"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

// REST shapes and supported headers are specified by:
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/developing-s3-tables-APIs.html
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html
func TestMultipartHTTPPersistsAttributesETagChecksumsAndRanges(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "http_multipart")
	base := strings.TrimPrefix(string(*table.WarehouseLocation), "s3://")
	object := "http://localhost/" + base + "/data/space%20%26%20%23.parquet"
	request := func(method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(f.ctx)
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		if !f.service.HandleData(w, r) {
			t.Fatal("private warehouse fell through")
		}
		return w
	}
	created := request(http.MethodPost, object+"?uploads", "", map[string]string{"Content-Type": "application/vnd.apache.parquet", "Cache-Control": "max-age=60", "Content-Disposition": "attachment", "Content-Language": "en", "Expires": "Wed, 04 Nov 2026 01:00:00 GMT", "X-Amz-Checksum-Algorithm": "SHA256", "X-Amz-Acl": "bucket-owner-full-control", "X-Amz-Storage-Class": "STANDARD", "X-Amz-Server-Side-Encryption": "AES256"})
	var upload struct {
		XMLName  xml.Name
		Key      string
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(created.Body.Bytes(), &upload); err != nil || created.Code != 200 || upload.UploadID == "" || upload.XMLName.Local != "InitiateMultipartUploadResult" || upload.Key != "data/space & #.parquet" {
		t.Fatalf("initiate: %d %s %v", created.Code, created.Body, err)
	}
	idQuery := "uploadId=" + url.QueryEscape(upload.UploadID)
	payload := "PAR1tiny native multipart payloadPAR1"
	sum := sha256.Sum256([]byte(payload))
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	part := request(http.MethodPut, object+"?"+idQuery+"&partNumber=1", payload, map[string]string{"X-Amz-Checksum-Sha256": checksum, "Content-Type": "application/octet-stream"})
	if part.Code != 200 || part.Header().Get("ETag") == "" || part.Header().Get("X-Amz-Checksum-Sha256") != checksum {
		t.Fatalf("upload: %d %s %v", part.Code, part.Body, part.Header())
	}
	listed := request(http.MethodGet, object+"?"+idQuery+"&max-parts=1", "", nil)
	var listing struct {
		XMLName           xml.Name
		Key               string
		ChecksumAlgorithm string
		StorageClass      string
		IsTruncated       bool
		Parts             []struct {
			PartNumber     int
			ETag           string
			ChecksumSHA256 string
		} `xml:"Part"`
	}
	if err := xml.Unmarshal(listed.Body.Bytes(), &listing); err != nil || listed.Code != 200 || listing.XMLName.Local != "ListPartsResult" || listing.StorageClass != "STANDARD" || listing.ChecksumAlgorithm != "SHA256" || listing.IsTruncated || len(listing.Parts) != 1 || listing.Parts[0].ETag != part.Header().Get("ETag") || listing.Parts[0].ChecksumSHA256 != checksum {
		t.Fatalf("list parts: %d %s %v", listed.Code, listed.Body, err)
	}
	completeBody := fmt.Sprintf(`<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Part><PartNumber>1</PartNumber><ETag>%s</ETag><ChecksumSHA256>%s</ChecksumSHA256></Part></CompleteMultipartUpload>`, part.Header().Get("ETag"), checksum)
	completed := request(http.MethodPost, object+"?"+idQuery, completeBody, map[string]string{"Content-Type": "application/xml", "If-None-Match": "*"})
	var result struct {
		XMLName        xml.Name
		ETag           string
		Key            string
		Location       string
		ChecksumSHA256 string
		ChecksumType   string
	}
	if err := xml.Unmarshal(completed.Body.Bytes(), &result); err != nil || completed.Code != 200 || result.XMLName.Local != "CompleteMultipartUploadResult" || result.ETag == "" || !strings.HasSuffix(result.ETag, "-1\"") || result.ChecksumType != "COMPOSITE" || !strings.HasSuffix(result.ChecksumSHA256, "-1") {
		t.Fatalf("complete: %d %s %v", completed.Code, completed.Body, err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		got := request(method, object, "", map[string]string{"X-Amz-Checksum-Mode": "ENABLED"})
		if got.Code != 200 || got.Header().Get("ETag") != result.ETag || got.Header().Get("Content-Type") != "application/vnd.apache.parquet" || got.Header().Get("Cache-Control") != "max-age=60" || got.Header().Get("X-Amz-Checksum-Sha256") != result.ChecksumSHA256 || got.Header().Get("Expires") != "Wed, 04 Nov 2026 01:00:00 GMT" {
			t.Fatalf("%s metadata: %d %v %s", method, got.Code, got.Header(), got.Body)
		}
		if method == http.MethodGet && got.Body.String() != payload || method == http.MethodHead && got.Body.Len() != 0 {
			t.Fatalf("%s bytes: %q", method, got.Body)
		}
		ranged := request(method, object, "", map[string]string{"Range": "bytes=1-3", "If-Match": result.ETag})
		if ranged.Code != 206 || ranged.Header().Get("Content-Length") != "3" || method == http.MethodGet && ranged.Body.String() != payload[1:4] || method == http.MethodHead && ranged.Body.Len() != 0 {
			t.Fatalf("%s range: %d %v %q", method, ranged.Code, ranged.Header(), ranged.Body)
		}
	}
	if got := request(http.MethodGet, object, "", map[string]string{"If-None-Match": result.ETag}); got.Code != 304 {
		t.Fatalf("conditional read: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodGet, object, "", map[string]string{"If-Match": `"wrong"`}); got.Code != 412 {
		t.Fatalf("failed condition: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodGet, object, "", map[string]string{"Range": "bytes=99999-"}); got.Code != 416 {
		t.Fatalf("invalid range: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodGet, object+"?"+idQuery, "", nil); got.Code != 404 || !strings.Contains(got.Body.String(), "NoSuchUpload") {
		t.Fatalf("consumed upload: %d %s", got.Code, got.Body)
	}
}

// Covers explicit CRC64 initiation and the local no-init inference path.
// The native AWS capture proves resulting full-object checksums, not the
// client's initiation headers or this complete request matrix.
func TestMultipartHTTPCRC64FullObject(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			f := newFixture(t, nil)
			table := f.create(t, "http_crc64")
			object := "http://localhost/" + strings.TrimPrefix(string(*table.WarehouseLocation), "s3://") + "/data/native.parquet"
			request := func(method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(f.ctx)
				for name, value := range headers {
					r.Header.Set(name, value)
				}
				w := httptest.NewRecorder()
				if !f.service.HandleData(w, r) {
					t.Fatal("private warehouse fell through")
				}
				return w
			}
			sum := func(data string) string {
				t.Helper()
				value, err := awschecksum.Sum("CRC64NVME", []byte(data))
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			// Sanitized native PyArrow/S3 Tables observation, 2026-11-05.
			if sum("123456789") != "rosUhgp5mIg=" {
				t.Fatalf("native CRC64NVME vector: %q", sum("123456789"))
			}
			if old := request("PUT", object, "old bytes", nil); old.Code != 200 {
				t.Fatalf("old object: %d %s", old.Code, old.Body)
			}
			headers := map[string]string{}
			if explicit {
				headers["X-Amz-Checksum-Algorithm"] = "CRC64NVME"
				headers["X-Amz-Checksum-Type"] = "FULL_OBJECT"
				bad := request("POST", object+"?uploads", "", map[string]string{"X-Amz-Checksum-Algorithm": "CRC64NVME", "X-Amz-Checksum-Type": "COMPOSITE"})
				if bad.Code != 400 || !strings.Contains(bad.Body.String(), "InvalidRequest") {
					t.Fatalf("composite initiation: %d %s", bad.Code, bad.Body)
				}
			}
			created := request("POST", object+"?uploads", "", headers)
			var upload struct {
				ID string `xml:"UploadId"`
			}
			if err := xml.Unmarshal(created.Body.Bytes(), &upload); err != nil || created.Code != 200 || upload.ID == "" {
				t.Fatalf("create: %d %s %v", created.Code, created.Body, err)
			}
			if explicit && created.Header().Get("X-Amz-Checksum-Type") != "FULL_OBJECT" {
				t.Fatalf("initiation type: %v", created.Header())
			}
			target := object + "?uploadId=" + url.QueryEscape(upload.ID)
			payloads := []string{strings.Repeat("a", 5*1024*1024), "PAR1tailPAR1"}
			manifest := "<CompleteMultipartUpload>"
			for i, payload := range payloads {
				partURL := fmt.Sprintf("%s&partNumber=%d", target, i+1)
				bad := request("PUT", partURL, payload, map[string]string{"X-Amz-Checksum-Crc64nvme": sum("wrong")})
				if bad.Code != 400 || !strings.Contains(bad.Body.String(), "BadDigest") {
					t.Fatalf("bad part: %d %s", bad.Code, bad.Body)
				}
				part := request("PUT", partURL, payload, map[string]string{"X-Amz-Checksum-Crc64nvme": sum(payload)})
				if part.Code != 200 || part.Header().Get("X-Amz-Checksum-Crc64nvme") != sum(payload) {
					t.Fatalf("part: %d %s %v", part.Code, part.Body, part.Header())
				}
				// FULL_OBJECT completion permits omitted part checksums.
				checksumXML := ""
				if i == 0 {
					checksumXML = "<ChecksumCRC64NVME>" + sum(payload) + "</ChecksumCRC64NVME>"
				}
				manifest += fmt.Sprintf("<Part><PartNumber>%d</PartNumber><ETag>%s</ETag>%s</Part>", i+1, part.Header().Get("ETag"), checksumXML)
			}
			manifest += "</CompleteMultipartUpload>"
			for _, name := range []string{"X-Amz-Checksum-Type", "X-Amz-Mp-Object-Size"} {
				r := httptest.NewRequest("POST", target, strings.NewReader(manifest)).WithContext(f.ctx)
				r.Header[name] = []string{"1", "1"}
				w := httptest.NewRecorder()
				if !f.service.HandleData(w, r) || w.Code != 400 {
					t.Fatalf("duplicate %s: %d %s", name, w.Code, w.Body)
				}
			}
			full := sum(payloads[0] + payloads[1])
			for _, tc := range []struct {
				name, body string
				headers    map[string]string
				code       string
			}{
				{"part", strings.Replace(manifest, sum(payloads[0]), sum("wrong"), 1), nil, "InvalidPart"},
				{"full", manifest, map[string]string{"X-Amz-Checksum-Crc64nvme": sum("wrong")}, "BadDigest"},
				{"type", manifest, map[string]string{"X-Amz-Checksum-Type": "COMPOSITE"}, "InvalidRequest"},
				{"size", manifest, map[string]string{"X-Amz-Mp-Object-Size": "1"}, "S3TablesUnsupportedHeader"},
				{"matching-size", manifest, map[string]string{"X-Amz-Mp-Object-Size": fmt.Sprint(len(payloads[0]) + len(payloads[1]))}, "S3TablesUnsupportedHeader"},
			} {
				got := request("POST", target, tc.body, tc.headers)
				if got.Code != 400 || !strings.Contains(got.Body.String(), tc.code) {
					t.Fatalf("%s: %d %s", tc.name, got.Code, got.Body)
				}
				if old := request("GET", object, "", nil); old.Code != 200 || old.Body.String() != "old bytes" {
					t.Fatalf("%s published failed completion: %d %s", tc.name, old.Code, old.Body)
				}
				listed := request("GET", target, "", nil)
				if listed.Code != 200 || !strings.Contains(listed.Body.String(), "<ChecksumCRC64NVME>"+sum(payloads[0])+"</ChecksumCRC64NVME>") || explicit && !strings.Contains(listed.Body.String(), "<ChecksumType>FULL_OBJECT</ChecksumType>") {
					t.Fatalf("%s lost parts: %d %s", tc.name, listed.Code, listed.Body)
				}
			}
			if rejected := request("POST", target, manifest, nil); rejected.Code != 412 {
				t.Fatalf("existing destination: %d %s", rejected.Code, rejected.Body)
			}
			if aborted := request("DELETE", target, "", nil); aborted.Code != 204 {
				t.Fatalf("abort rejected upload: %d %s", aborted.Code, aborted.Body)
			}
			object += ".new"
			created = request("POST", object+"?uploads", "", headers)
			if err := xml.Unmarshal(created.Body.Bytes(), &upload); err != nil || created.Code != 200 {
				t.Fatalf("create fresh upload: %d %s %v", created.Code, created.Body, err)
			}
			target = object + "?uploadId=" + url.QueryEscape(upload.ID)
			manifest = "<CompleteMultipartUpload>"
			for i, payload := range payloads {
				part := request("PUT", fmt.Sprintf("%s&partNumber=%d", target, i+1), payload, map[string]string{"X-Amz-Checksum-Crc64nvme": sum(payload)})
				if part.Code != 200 {
					t.Fatalf("fresh part: %d %s", part.Code, part.Body)
				}
				checksumXML := ""
				if i == 0 {
					checksumXML = "<ChecksumCRC64NVME>" + part.Header().Get("X-Amz-Checksum-Crc64nvme") + "</ChecksumCRC64NVME>"
				}
				manifest += fmt.Sprintf("<Part><PartNumber>%d</PartNumber><ETag>%s</ETag>%s</Part>", i+1, part.Header().Get("ETag"), checksumXML)
			}
			manifest += "</CompleteMultipartUpload>"
			completed := request("POST", target, manifest, map[string]string{"X-Amz-Checksum-Crc64nvme": full, "X-Amz-Checksum-Type": "FULL_OBJECT"})
			var result struct{ ChecksumCRC64NVME, ChecksumType string }
			if err := xml.Unmarshal(completed.Body.Bytes(), &result); err != nil || completed.Code != 200 || result.ChecksumCRC64NVME != full || result.ChecksumType != "FULL_OBJECT" || completed.Header().Get("X-Amz-Checksum-Crc64nvme") != full || completed.Header().Get("X-Amz-Checksum-Type") != "FULL_OBJECT" {
				t.Fatalf("complete: %d %s %v %v", completed.Code, completed.Body, completed.Header(), err)
			}
			for _, method := range []string{"GET", "HEAD"} {
				got := request(method, object, "", map[string]string{"X-Amz-Checksum-Mode": "enabled"})
				if got.Code != 200 || got.Header().Get("X-Amz-Checksum-Crc64nvme") != full || got.Header().Get("X-Amz-Checksum-Type") != "FULL_OBJECT" || method == "GET" && got.Body.String() != payloads[0]+payloads[1] || method == "HEAD" && got.Body.Len() != 0 {
					t.Fatalf("%s: %d %v", method, got.Code, got.Header())
				}
			}
		})
	}
}

func TestMultipartHTTPRejectsUnsupportedOptionsAndMalformedRequests(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "http_rejections")
	base := "http://localhost/" + strings.TrimPrefix(string(*table.WarehouseLocation), "s3://")
	object := base + "/data/native.avro"
	request := func(method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(f.ctx)
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		if !f.service.HandleData(w, r) {
			t.Fatal("reserved request fell through")
		}
		return w
	}
	for _, tc := range []struct {
		name, method, target, body string
		headers                    map[string]string
		status                     int
	}{
		{"list-v1", "GET", base, "", nil, 501},
		{"list-v2", "GET", base + "?list-type=2", "", nil, 501},
		{"delete", "DELETE", object, "", nil, 501},
		{"delete-many", "POST", base + "?delete", "<Delete/>", nil, 501},
		{"copy", "PUT", object, "", map[string]string{"X-Amz-Copy-Source": "/bucket/source"}, 501},
		{"copy-part", "PUT", object + "?uploadId=unknown&partNumber=1", "", map[string]string{"X-Amz-Copy-Source": "/bucket/source"}, 501},
		{"tagging", "POST", object + "?uploads", "", map[string]string{"X-Amz-Tagging": "key=value"}, 501},
		{"kms", "POST", object + "?uploads", "", map[string]string{"X-Amz-Server-Side-Encryption": "aws:kms"}, 400},
		{"acl", "POST", object + "?uploads", "", map[string]string{"X-Amz-Acl": "public-read"}, 400},
		{"storage", "POST", object + "?uploads", "", map[string]string{"X-Amz-Storage-Class": "GLACIER"}, 400},
		{"owner", "POST", object + "?uploads", "", map[string]string{"X-Amz-Expected-Bucket-Owner": "999999999999"}, 403},
		{"algorithm", "POST", object + "?uploads", "", map[string]string{"X-Amz-Checksum-Algorithm": "UNKNOWN"}, 501},
		{"duplicate-query", "POST", object + "?uploads&uploads", "", nil, 400},
		{"empty-id", "PUT", object + "?uploadId=&partNumber=1", "abc", nil, 400},
		{"zero-part", "PUT", object + "?uploadId=unknown&partNumber=0", "abc", nil, 400},
		{"negative-part", "PUT", object + "?uploadId=unknown&partNumber=-1", "abc", nil, 400},
		{"overflow-part", "PUT", object + "?uploadId=unknown&partNumber=10001", "abc", nil, 400},
		{"unexpected-body", "POST", object + "?uploads", "not empty", nil, 400},
		{"bad-xml", "POST", object + "?uploadId=unknown", "<CompleteMultipartUpload><Part>", nil, 400},
		{"empty-parts", "POST", object + "?uploadId=unknown", "<CompleteMultipartUpload/>", nil, 400},
		{"duplicate-field", "POST", object + "?uploadId=unknown", `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><PartNumber>2</PartNumber><ETag>etag</ETag></Part></CompleteMultipartUpload>`, nil, 400},
		{"unknown-checksum", "POST", object + "?uploadId=unknown", `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag><ChecksumUnknown>1234</ChecksumUnknown></Part></CompleteMultipartUpload>`, nil, 400},
		{"trailing-xml", "POST", object + "?uploadId=unknown", `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag></Part></CompleteMultipartUpload><extra/>`, nil, 400},
		{"form-body", "POST", object + "?uploadId=unknown", `<CompleteMultipartUpload/>`, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := request(tc.method, tc.target, tc.body, tc.headers)
			if got.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", got.Code, tc.status, got.Body)
			}
		})
	}
	created := request("POST", object+"?uploads", "", nil)
	var upload struct {
		ID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(created.Body.Bytes(), &upload); err != nil || created.Code != 200 || upload.ID == "" {
		t.Fatalf("initiate: %d %s %v", created.Code, created.Body, err)
	}
	uploadURL := object + "?uploadId=" + url.QueryEscape(upload.ID)
	for _, n := range []int{2, 7} {
		if got := request("PUT", fmt.Sprintf("%s&partNumber=%d", uploadURL, n), "part", nil); got.Code != 200 {
			t.Fatalf("part: %d %s", got.Code, got.Body)
		}
	}
	first := request("GET", uploadURL+"&max-parts=1", "", nil)
	if first.Code != 200 || !strings.Contains(first.Body.String(), "<IsTruncated>true</IsTruncated>") || !strings.Contains(first.Body.String(), "<NextPartNumberMarker>2</NextPartNumberMarker>") {
		t.Fatalf("first page: %d %s", first.Code, first.Body)
	}
	last := request("GET", uploadURL+"&max-parts=1&part-number-marker=2", "", nil)
	if last.Code != 200 || !strings.Contains(last.Body.String(), "<PartNumber>7</PartNumber>") || !strings.Contains(last.Body.String(), "<IsTruncated>false</IsTruncated>") {
		t.Fatalf("last page: %d %s", last.Code, last.Body)
	}
	if got := request("DELETE", uploadURL, "", nil); got.Code != 204 {
		t.Fatalf("abort: %d %s", got.Code, got.Body)
	}
	if got := request("GET", uploadURL, "", nil); got.Code != 404 || !strings.Contains(got.Body.String(), "NoSuchUpload") {
		t.Fatalf("aborted upload: %d %s", got.Code, got.Body)
	}
	if got := request("GET", object, "", nil); got.Code != 404 {
		t.Fatalf("abort published object: %d %s", got.Code, got.Body)
	}
}

func TestObjectHTTPPutPersistsSupportedHeadersAndConditions(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "http_put")
	object := "http://localhost/" + strings.TrimPrefix(string(*table.WarehouseLocation), "s3://") + "/data/test.avro"
	request := func(method, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, object, strings.NewReader(body)).WithContext(f.ctx)
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		if !f.service.HandleData(w, r) {
			t.Fatal("reserved object fell through")
		}
		return w
	}
	payload := "Obj\x01actual avro bytes"
	sum := sha256.Sum256([]byte(payload))
	checksum := base64.StdEncoding.EncodeToString(sum[:])
	created := request("PUT", payload, map[string]string{"Content-Type": "application/avro", "Content-Encoding": "identity", "Content-Language": "en-US", "Cache-Control": "no-cache", "Content-Disposition": "inline", "X-Amz-Checksum-Sha256": checksum, "X-Amz-Sdk-Checksum-Algorithm": "SHA256", "If-None-Match": "*"})
	if created.Code != 200 || created.Header().Get("X-Amz-Checksum-Sha256") != checksum {
		t.Fatalf("put: %d %v %s", created.Code, created.Header(), created.Body)
	}
	for _, method := range []string{"GET", "HEAD"} {
		got := request(method, "", map[string]string{"X-Amz-Checksum-Mode": "ENABLED"})
		if got.Code != 200 || got.Header().Get("ETag") != created.Header().Get("ETag") || got.Header().Get("Content-Type") != "application/avro" || got.Header().Get("Content-Encoding") != "identity" || got.Header().Get("Content-Language") != "en-US" || got.Header().Get("X-Amz-Checksum-Sha256") != checksum || got.Header().Get("X-Amz-Server-Side-Encryption") != "AES256" || got.Header().Get("Last-Modified") == "" {
			t.Fatalf("%s: %d %v %s", method, got.Code, got.Header(), got.Body)
		}
	}
	if got := request("PUT", "replacement", map[string]string{"If-None-Match": "*"}); got.Code != 412 {
		t.Fatalf("conditional put: %d %s", got.Code, got.Body)
	}
	if got := request("PUT", "replacement", map[string]string{"Content-MD5": "AAAAAAAAAAAAAAAAAAAAAA=="}); got.Code != 400 || !strings.Contains(got.Body.String(), "BadDigest") {
		t.Fatalf("corrupt put: %d %s", got.Code, got.Body)
	}
	if got := request("GET", "", nil); got.Code != 200 || got.Body.String() != payload || got.Header().Get("ETag") != created.Header().Get("ETag") {
		t.Fatalf("failed writes changed destination: %d %s", got.Code, got.Body)
	}
	if got := request("HEAD", "", map[string]string{"Range": "bytes=-4"}); got.Code != 206 || got.Header().Get("Content-Length") != "4" || got.Body.Len() != 0 {
		t.Fatalf("suffix head: %d %v %s", got.Code, got.Header(), got.Body)
	}
	if got := request("GET", "", map[string]string{"If-Match": `"wrong"`}); got.Code != 412 || got.Header().Get("Content-Encoding") != "" {
		t.Fatalf("precondition error retained object encoding: %d %v %s", got.Code, got.Header(), got.Body)
	}
}

// The primary permissions table maps ListParts to GetTableData, not
// PutTableData: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-tables-setting-up.html
func TestMultipartHTTPListPartsUsesCurrentReadPermission(t *testing.T) {
	identities := iam.NewMemoryRepository(nil)
	identityService := iam.NewWithConfig(iam.Config{Repository: identities})
	authorizer := authorization.NewWithClock(identityService, nil, nil)
	f := newFixture(t, authorizer)
	table := f.create(t, "http_parts_iam")
	object := "http://localhost/" + strings.TrimPrefix(string(*table.WarehouseLocation), "s3://") + "/data/parts.parquet"
	initiate := httptest.NewRequest("POST", object+"?uploads", nil).WithContext(f.ctx)
	created := httptest.NewRecorder()
	f.service.HandleData(created, initiate)
	var upload struct {
		ID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(created.Body.Bytes(), &upload); err != nil || created.Code != 200 || upload.ID == "" {
		t.Fatalf("initiate: %d %s %v", created.Code, created.Body, err)
	}
	user := iam.User{UserName: "partsreader", UserId: "AIDAPARTSREADER", Arn: "arn:aws:iam::123456789012:user/partsreader", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	caller := awsctx.WithMetadata(f.ctx, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId})
	for _, tc := range []struct {
		action string
		status int
	}{{"GetTableData", 200}, {"PutTableData", 403}, {"GetTableData", 200}} {
		user.IdentityPolicies.Inline["parts"] = fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"s3tables:%s","Resource":"*"}]}`, tc.action)
		if err := identities.Update(f.ctx, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
		}); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", object+"?uploadId="+url.QueryEscape(upload.ID), nil).WithContext(caller)
		w := httptest.NewRecorder()
		if !f.service.HandleData(w, r) || w.Code != tc.status {
			t.Fatalf("%s list parts: %d %s", tc.action, w.Code, w.Body)
		}
	}
}
