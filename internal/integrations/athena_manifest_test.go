package integrations

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
)

func TestAthenaManifestRecordsOnlySuccessfulCommittedObjects(t *testing.T) {
	owner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, _ := awsapi.FromContext(r.Context())
		switch in := decoded.Input.(type) {
		case *api.PutObjectInput:
			if string(*in.Key) == "denied" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		case *api.DeleteObjectsInput:
			w.Write([]byte(`<DeleteResult><Deleted><Key>temporary</Key></Deleted><Error><Key>kept</Key><Code>AccessDenied</Code></Error></DeleteResult>`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	bridge := &athenaDataPlane{execution: context.Background(), s3: owner}
	call := func(method, path, body string) {
		t.Helper()
		r := httptest.NewRequest(method, "http://callback"+path, strings.NewReader(body))
		checksum := md5.Sum([]byte(body))
		r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(checksum[:]))
		bridge.ServeHTTP(httptest.NewRecorder(), r)
	}
	call("PUT", "/data/committed", "object")
	call("PUT", "/data/committed", "retry")
	call("PUT", "/data/denied", "not committed")
	call("PUT", "/data/part-only?partNumber=1&uploadId=upload", "part")
	call("POST", "/data/multipart?uploadId=upload", `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag></Part></CompleteMultipartUpload>`)
	call("PUT", "/data/temporary", "object")
	call("PUT", "/data/kept", "object")
	call("PUT", "/data/deleted", "object")
	call("DELETE", "/data/deleted", "")
	call("POST", "/data?delete", `<Delete><Object><Key>temporary</Key></Object><Object><Key>kept</Key></Object></Delete>`)
	want := "s3://data/committed\ns3://data/kept\ns3://data/multipart\n"
	if got := string(bridge.manifest()); got != want {
		t.Fatalf("manifest = %q; want %q", got, want)
	}
	if empty := (&athenaDataPlane{}).manifest(); empty == nil || len(empty) != 0 {
		t.Fatalf("zero-object manifest = %q", empty)
	}
}
