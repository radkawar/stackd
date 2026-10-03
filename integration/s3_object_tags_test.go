package stackd_test

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd"
	"stackd/clock"
)

type s3TagCall struct {
	s3KMSCall
	Tags           map[string]string
	AdvanceSeconds int
	RawXML         string
	Headers        map[string]string
	AbsentHeaders  []string
}

// Native captures retain wire responses and source sequence positions. The
// compact cases compare tag sets without promising a native iteration order.
func TestS3ObjectTaggingNativeReplay(t *testing.T) {
	for _, name := range []string{"controls", "authority"} {
		t.Run(name, func(t *testing.T) {
			s3ObjectNativeReplay(t, "s3/object_tagging_"+name+"_replay.json.gz")
		})
	}
}

func TestS3CopyObjectNativeReplay(t *testing.T) {
	for _, name := range []string{"controls", "encryption", "supplement"} {
		t.Run(name, func(t *testing.T) {
			s3ObjectNativeReplay(t, "s3/copy_"+name+"_replay.json.gz")
		})
	}
}

func s3ObjectNativeReplay(t *testing.T, path string) {
	t.Helper()
	var fixture struct {
		Cases []struct {
			Name  string
			Calls []s3TagCall
		}
	}
	awsReadFixture(t, path, &fixture)
	for _, scenario := range fixture.Cases {
		t.Run(scenario.Name, func(t *testing.T) {
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					source := clock.NewManual(time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC))
					clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
						return startPublicCloud(t, config)
					})
					replay := newS3KMSReplay(clients)
					for _, row := range scenario.Calls {
						if row.Reopen {
							replay.clients = reopen()
						}
						if row.AdvanceSeconds != 0 {
							advanceClock(t, source, time.Duration(row.AdvanceSeconds)*time.Second)
						}
						if !t.Run(row.Label, func(t *testing.T) {
							wire := &s3VersionHTTPClient{HTTPClient: replay.clients.server.Client()}
							replay.httpClient = wire
							var out any
							if row.RawXML != "" {
								s3TagRawCall(t, replay, wire, row)
							} else {
								out = replay.call(t, row.s3KMSCall)
							}
							s3TagCheck(t, replay, wire, row, out)
						}) {
							return
						}
					}
				})
			}
		})
	}
}

func s3TagCheck(t *testing.T, replay *s3KMSReplay, wire *s3VersionHTTPClient, row s3TagCall, out any) {
	t.Helper()
	if row.Tags != nil {
		var want map[string]string
		if err := json.Unmarshal(replay.rebind(t, row.Tags), &want); err != nil {
			t.Fatal(err)
		}
		tags := out.(*s3.GetObjectTaggingOutput).TagSet
		got := make(map[string]string, len(tags))
		for _, tag := range tags {
			got[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		if len(tags) != len(want) || !reflect.DeepEqual(got, want) {
			t.Fatalf("tag set = %#v; native %#v", got, want)
		}
	}
	var headers map[string]string
	if err := json.Unmarshal(replay.rebind(t, row.Headers), &headers); err != nil {
		t.Fatal(err)
	}
	for name, want := range headers {
		if got := wire.header.Get(name); got != want {
			t.Fatalf("%s = %q; native %q", name, got, want)
		}
	}
	for _, name := range row.AbsentHeaders {
		if values, present := wire.header[http.CanonicalHeaderKey(name)]; present {
			t.Fatalf("exposed header %s omitted by native response: %v", name, values)
		}
	}
	if row.ErrorDetails != nil {
		assertS3ErrorDetails(t, wire.body, row.ErrorDetails)
	}
}

func s3TagRawCall(t *testing.T, replay *s3KMSReplay, wire *s3VersionHTTPClient, row s3TagCall) {
	t.Helper()
	var input struct {
		Bucket, Key, ExpectedBucketOwner string
		VersionId                        *string
	}
	if err := json.Unmarshal(replay.rebind(t, row.Input), &input); err != nil {
		t.Fatal(err)
	}
	endpoint := replay.clients.server.URL + "/" + url.PathEscape(input.Bucket)
	if row.Operation == "PutObjectTagging" {
		endpoint += "/" + url.PathEscape(input.Key)
	} else if row.Operation != "PutBucketTagging" {
		t.Fatalf("unsupported raw tagging operation %s", row.Operation)
	}
	query := url.Values{"tagging": []string{""}}
	if input.VersionId != nil {
		query.Set("versionId", *input.VersionId)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, endpoint+"?"+query.Encode(), strings.NewReader(row.RawXML))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/xml")
	if owner := input.ExpectedBucketOwner; owner != "" {
		request.Header.Set("x-amz-expected-bucket-owner", owner)
	}
	md5sum := md5.Sum([]byte(row.RawXML))
	request.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(md5sum[:]))
	digest := sha256.Sum256([]byte(row.RawXML))
	request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(digest[:]))
	if err := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true }).SignHTTP(t.Context(), replay.sessions[row.Actor], request, hex.EncodeToString(digest[:]), "s3", "us-east-1", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	code := row.Code
	if code == "Success" {
		code = ""
	}
	s3HTTPResponse(t, wire, request, row.Status, code)
}
