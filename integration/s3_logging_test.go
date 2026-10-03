package stackd_test

import (
	"io"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
)

type s3LoggingRecordReference struct {
	ObjectIndex, RecordIndex int
	Bucket, Key              string
}

type s3LoggingRequest struct {
	s3MultipartEventCall
	Actor                       string
	Native                      []s3LoggingRecordReference
	Destination, Prefix, Format string
	Absent                      bool
}

type s3LoggingObserved struct {
	request         s3LoggingRequest
	wire            s3MultipartEventWire
	host, requester string
	at              time.Time
}

type s3LoggingObject struct {
	Bucket, Key string
	Metadata    struct{ ContentType, ServerSideEncryption string }
	ACL         s3.GetObjectAclOutput
	Records     []s3LoggingNativeRecord
}

type s3LoggingNativeRecord struct {
	Fields []string
	// Fixed literals observed before capture sanitization, never credentials.
	QueryRedactions map[string]string
}

// Local records cover documented legacy ACLs and internal accounting, not
// fabricated references into the native BOE delivery capture.
type s3LoggingLocalRecord struct {
	Destination, Bucket, Operation, Key string
	Fields                              map[int]string
}

// Native references identify delivered objects and individual request-correlated
// records, never a batch count or a provider delivery-latency promise. Advances
// below exercise the emulator's documented local scheduling bounds instead.
func TestS3NativeLoggingDelivery(t *testing.T) {
	s3LoggingDelivery(t, "s3/logging_delivery_replay.json")
}

func TestS3LocalLoggingDelivery(t *testing.T) {
	s3LoggingDelivery(t, "s3/logging_local_replay.json")
}

func s3LoggingDelivery(t *testing.T, path string) {
	t.Helper()
	var fixture struct {
		Scenarios []struct {
			Name, Evidence string
			Start          time.Time
			Source         string
			Destinations   []string
			Setup          []s3KMSCall
			Steps          []struct {
				Label                  string
				Calls                  []s3KMSCall
				Requests               []s3LoggingRequest
				LocalRecords           []s3LoggingLocalRecord
				Advance                string
				Reopen, Denied, Verify bool
			}
		}
	}
	awsReadFixture(t, path, &fixture)
	for _, scenario := range fixture.Scenarios {
		var evidence struct {
			DeliveredObjects []s3LoggingObject `json:"delivered_objects"`
		}
		if scenario.Evidence != "" {
			awsReadFixture(t, scenario.Evidence, &evidence)
		}
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				source := clock.NewManual(scenario.Start)
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
				replay := newS3KMSReplay(clients)
				arn, key, secret := clients.user(t, "test", "Delegated")
				putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"s3:*"`, "*"))
				replay.sessions["signed"] = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
				for _, row := range scenario.Setup {
					replay.call(t, row)
				}
				owner, err := replay.s3Client("caller").GetBucketAcl(t.Context(), &s3.GetBucketAclInput{Bucket: &scenario.Source})
				if err != nil {
					t.Fatal(err)
				}
				canonical := aws.ToString(owner.Owner.ID)
				requesters := map[string]string{"signed": arn, "caller": canonical, "anonymous": "-"}
				observed := map[string]s3LoggingObserved{}
				for _, step := range scenario.Steps {
					if !t.Run(step.Label, func(t *testing.T) {
						if step.Reopen {
							replay.clients = reopen()
						}
						for _, row := range step.Calls {
							replay.call(t, row)
						}
						for _, row := range step.Requests {
							if !row.Absent && len(row.Native) == 0 {
								t.Fatalf("request %q has no native record references", row.Label)
							}
							capture := &s3AttributesAuditWire{Client: replay.clients.server.Client()}
							replay.httpClient = capture
							credentials, ok := replay.sessions[row.Actor]
							if !ok {
								t.Fatalf("unknown actor %q", row.Actor)
							}
							requester := requesters[row.Actor]
							if requester == "" {
								identity, err := replay.clients.sts(credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
								if err != nil {
									t.Fatal(err)
								}
								requester = aws.ToString(identity.Arn)
								requesters[row.Actor] = requester
							}
							wire := s3MultipartEventRequest(t, replay, credentials, row.s3MultipartEventCall, source.Now())
							replay.httpClient = nil
							if wire.id == "" || wire.extended == "" {
								t.Fatal("public request omitted correlation IDs")
							}
							if _, duplicate := observed[wire.id]; duplicate {
								t.Fatal("public request reused correlation ID")
							}
							observed[wire.id] = s3LoggingObserved{request: row, wire: wire, host: capture.host, requester: requester, at: source.Now()}
						}
						if step.Advance != "" {
							duration, err := time.ParseDuration(step.Advance)
							if err != nil {
								t.Fatal(err)
							}
							advanceClock(t, source, duration)
							trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
						}
						if !step.Denied && !step.Verify {
							return
						}
						type recordMatch struct {
							requestID string
							index     int
						}
						found := map[recordMatch]bool{}
						localFound := make([]bool, len(step.LocalRecords))
						for _, destination := range scenario.Destinations {
							client := replay.s3Client("caller")
							pages := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &destination})
							for pages.HasMorePages() {
								page, err := pages.NextPage(t.Context())
								if err != nil {
									t.Fatal(err)
								}
								if step.Denied && len(page.Contents) != 0 {
									t.Fatalf("delivery bypassed destination authorization: %s", destination)
								}
								for _, object := range page.Contents {
									out, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &destination, Key: object.Key})
									if err != nil {
										t.Fatal(err)
									}
									body, err := io.ReadAll(out.Body)
									closeErr := out.Body.Close()
									if err != nil || closeErr != nil {
										t.Fatalf("reading log object: %v %v", err, closeErr)
									}
									for _, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
										fields := s3LoggingFields.FindAllString(line, -1)
										if len(fields) != 27 {
											t.Fatalf("log object %s: expected 27 fields, got %d: %s", aws.ToString(object.Key), len(fields), line)
										}
										for i, expected := range step.LocalRecords {
											if destination != expected.Destination || fields[1] != expected.Bucket || fields[6] != expected.Operation || fields[7] != expected.Key {
												continue
											}
											for index, want := range expected.Fields {
												if index < 0 || index >= len(fields) || fields[index] != want {
													t.Fatalf("local %s field %d: got %v, want %q", expected.Operation, index, fields, want)
												}
											}
											if aws.ToString(out.ContentType) != "text/plain" || out.ServerSideEncryption != types.ServerSideEncryptionAes256 {
												t.Fatalf("local log object content type/encryption differs: %+v", out)
											}
											acl, err := client.GetObjectAcl(t.Context(), &s3.GetObjectAclInput{Bucket: &destination, Key: object.Key})
											if err != nil {
												t.Fatal(err)
											}
											s3LoggingLegacyACL(t, acl, canonical)
											localFound[i] = true
										}
										request, selected := observed[fields[5]]
										if !selected {
											continue
										}
										if request.request.Absent {
											t.Fatalf("disabled source delivered request %s", fields[5])
										}
										for index, ref := range request.request.Native {
											if ref.ObjectIndex < 0 || ref.ObjectIndex >= len(evidence.DeliveredObjects) {
												t.Fatalf("invalid native object reference: %+v", ref)
											}
											native := evidence.DeliveredObjects[ref.ObjectIndex]
											if native.Bucket != ref.Bucket || native.Key != ref.Key || ref.RecordIndex < 0 || ref.RecordIndex >= len(native.Records) {
												t.Fatalf("stale native source reference: %+v", ref)
											}
											expected := native.Records[ref.RecordIndex]
											if len(expected.Fields) != 27 {
												t.Fatal("native reference does not contain 27 fields")
											}
											if fields[1] != expected.Fields[1] || fields[6] != expected.Fields[6] || fields[7] != expected.Fields[7] {
												continue
											}
											t.Logf("native %s: delivered_objects[%d].records[%d]", scenario.Evidence, ref.ObjectIndex, ref.RecordIndex)
											s3LoggingCompare(t, fields, expected, request, canonical)
											s3LoggingKey(t, destination, aws.ToString(object.Key), request, scenario.Source, source.Now())
											if aws.ToString(out.ContentType) != native.Metadata.ContentType || string(out.ServerSideEncryption) != native.Metadata.ServerSideEncryption {
												t.Fatalf("native log object content type/encryption differs: %+v", out)
											}
											acl, err := client.GetObjectAcl(t.Context(), &s3.GetObjectAclInput{Bucket: &destination, Key: object.Key})
											if err != nil {
												t.Fatal(err)
											}
											s3LoggingACL(t, acl, native, canonical, replay.values)
											found[recordMatch{fields[5], index}] = true
										}
									}
								}
							}
						}
						if step.Verify {
							for i, expected := range step.LocalRecords {
								if !localFound[i] {
									t.Fatalf("missing local %s for %s/%s after delivery/reopen", expected.Operation, expected.Bucket, expected.Key)
								}
							}
							for id, request := range observed {
								if request.request.Absent {
									continue
								}
								for index := range request.request.Native {
									if !found[recordMatch{id, index}] {
										t.Fatalf("missing native-correlated request %s (%s), record %d after delivery/reopen", id, request.request.Label, index)
									}
								}
							}
						}
					}) {
						return
					}
				}
			})
		}
	}
}

var s3LoggingFields = regexp.MustCompile(`\[[^\]]*\]|"(?:\\.|[^"\\])*"|\S+`)

func s3LoggingCompare(t *testing.T, got []string, reference s3LoggingNativeRecord, request s3LoggingObserved, canonical string) {
	t.Helper()
	native := reference.Fields
	want := append([]string(nil), native...)
	want[0] = canonical
	want[2] = request.at.UTC().Format("[02/Jan/2006:15:04:05 -0700]")
	if net.ParseIP(got[3]) == nil {
		t.Fatalf("invalid public remote address %q", got[3])
	}
	want[3] = got[3]
	if want[4] != "-" {
		want[4] = request.requester
	}
	want[5], want[18], want[22] = request.wire.id, request.wire.extended, request.host
	if native[8] != "-" {
		if request.wire.status != intMustS3Logging(t, native[9]) {
			t.Fatal("native HTTP outcome changed")
		}
		// Signers may reorder the incoming query; logs must retain the actual
		// wire URI, including locally generated upload and version identifiers.
		target := request.wire.target.RequestURI()
		query := request.wire.target.Query()
		for name, literal := range reference.QueryRedactions {
			values := query[name]
			if len(values) == 0 {
				t.Fatalf("request omits native query parameter %s", name)
			}
			for _, value := range values {
				target = strings.ReplaceAll(target, url.QueryEscape(value), url.QueryEscape(literal))
			}
		}
		want[8] = strconv.Quote(request.request.Method + " " + target + " HTTP/1.1")
		if want[17] != "-" {
			want[17] = query.Get("versionId")
		}
		// HTTP accounting measures the actual public reply, including legal XML
		// serialization differences and locally generated identifiers. A copy's
		// internal source record has no URI or independent byte measurement.
		want[11] = "-"
		if request.wire.bytesOut != 0 {
			want[11] = strconv.Itoa(request.wire.bytesOut)
		}
	}
	for _, index := range []int{13, 14} {
		if native[index] == "-" {
			continue
		}
		if intMustS3Logging(t, got[index]) < 0 {
			t.Fatalf("negative request duration: %s", got[index])
		}
		want[index] = got[index]
	}
	// The retained public test listener is HTTP, unlike native REST's TLS.
	want[20], want[23] = "-", "-"
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("native log fields differ\n got: %#v\nwant: %#v", got, want)
	}
}

func intMustS3Logging(t *testing.T, text string) int {
	t.Helper()
	value, err := strconv.Atoi(text)
	if err != nil {
		t.Fatalf("invalid numeric log field %q", text)
	}
	return value
}

func s3LoggingKey(t *testing.T, destination, key string, observed s3LoggingObserved, source string, deliveredAt time.Time) {
	t.Helper()
	request := observed.request
	if destination != request.Destination {
		t.Fatalf("pending request redirected to %s, want retained %s", destination, request.Destination)
	}
	at := deliveredAt.UTC()
	prefix := request.Prefix
	if request.Format != "SimplePrefix" {
		if request.Format != "DeliveryTime" {
			at = observed.at.UTC()
		}
		prefix += "123456789012/us-east-1/" + source + "/" + at.Format("2006/01/02/")
		if request.Format != "DeliveryTime" {
			at = time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
		}
	}
	prefix += at.Format("2006-01-02-15-04-05-")
	if !strings.HasPrefix(key, prefix) || len(key) == len(prefix) {
		t.Fatalf("native key layout %q, got %q", prefix+"<unique>", key)
	}
}

func s3LoggingACL(t *testing.T, got *s3.GetObjectAclOutput, native s3LoggingObject, canonical string, bindings map[string]string) {
	t.Helper()
	if got.Owner == nil || native.ACL.Owner == nil || len(native.Records) == 0 || len(native.Records[0].Fields) != 27 {
		t.Fatal("native log object owner or source record is missing")
	}
	nativeBucketOwner := native.Records[0].Fields[0]
	nativeObjectOwner, objectOwner := aws.ToString(native.ACL.Owner.ID), aws.ToString(got.Owner.ID)
	if objectOwner == "" || (nativeObjectOwner == nativeBucketOwner) != (objectOwner == canonical) {
		t.Fatalf("native log object ownership changed: %+v", got.Owner)
	}
	type grantKey struct{ kind, id, uri, permission string }
	grants := make(map[grantKey]int)
	for _, grant := range native.ACL.Grants {
		if grant.Grantee == nil {
			t.Fatal("native log object grant has no grantee")
		}
		id := aws.ToString(grant.Grantee.ID)
		switch id {
		case nativeBucketOwner:
			id = canonical
		case nativeObjectOwner:
			id = objectOwner
		default:
			if bound, ok := bindings[id]; ok {
				id = bound
			}
		}
		grants[grantKey{string(grant.Grantee.Type), id, aws.ToString(grant.Grantee.URI), string(grant.Permission)}]++
	}
	for _, grant := range got.Grants {
		if grant.Grantee == nil {
			t.Fatal("delivered log object grant has no grantee")
		}
		key := grantKey{string(grant.Grantee.Type), aws.ToString(grant.Grantee.ID), aws.ToString(grant.Grantee.URI), string(grant.Permission)}
		if grants[key] == 0 {
			t.Fatalf("unexpected delivered log object grant: %+v", key)
		}
		grants[key]--
	}
	for grant, count := range grants {
		if count != 0 {
			t.Fatalf("missing native log object grant: %+v", grant)
		}
	}
}

func s3LoggingLegacyACL(t *testing.T, got *s3.GetObjectAclOutput, canonical string) {
	t.Helper()
	if got.Owner == nil || aws.ToString(got.Owner.ID) == "" || aws.ToString(got.Owner.ID) == canonical {
		t.Fatalf("legacy log object is not owned by the log delivery account: %+v", got)
	}
	owners := map[string]bool{aws.ToString(got.Owner.ID): false, canonical: false}
	for _, grant := range got.Grants {
		if grant.Grantee == nil || grant.Grantee.Type != types.TypeCanonicalUser || grant.Permission != types.PermissionFullControl {
			t.Fatalf("unexpected legacy log grant: %+v", grant)
		}
		id := aws.ToString(grant.Grantee.ID)
		if _, ok := owners[id]; !ok {
			t.Fatalf("legacy log grants access to an unrelated owner: %s", id)
		}
		owners[id] = true
	}
	for id, granted := range owners {
		if !granted {
			t.Fatalf("legacy log owner %s lacks FULL_CONTROL: %+v", id, got)
		}
	}
}
