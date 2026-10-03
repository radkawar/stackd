package stackd_test

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestStepFunctionsNativeSDKRequests(t *testing.T) {
	var fixture struct {
		stepFunctionsNativeFixture
		Prefix string
	}
	awsReadFixture(t, "stepfunctions/sdk_requests.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := stepFunctionsTaskCloud(t, backend, fixture.stepFunctionsNativeFixture, time.UnixMilli(fixture.Observations[0].Started))
			for _, captured := range fixture.Observations {
				if stepFunctionsOperation(captured.Operation) == "getcalleridentity" {
					continue
				}
				var outcome struct{ Error, Cause string }
				if len(captured.Result.Output) != 0 {
					awsDecodeJSON(t, captured.Result.Output, &outcome)
				}
				if outcome.Error == "States.TaskFailed" && strings.HasPrefix(outcome.Cause, "The principal states.amazonaws.com is not authorized to assume") {
					// Retain the settled retry, not native IAM propagation latency.
					continue
				}
				if !t.Run(captured.Label, func(t *testing.T) {
					if strings.HasSuffix(captured.Label, "-retained") {
						r.clients = r.reopen()
					}
					if captured.Label == "boolean-true" {
						// Native canonical owner IDs are opaque. Bind to the actual
						// bucket ACL owner, not an arbitrary nonempty list result.
						var envelope struct{ Output string }
						awsDecodeJSON(t, captured.Result.Output, &envelope)
						var listed struct {
							Contents []struct{ Owner struct{ Id string } }
						}
						awsDecodeJSON(t, []byte(envelope.Output), &listed)
						if len(listed.Contents) == 0 || listed.Contents[0].Owner.Id == "" {
							t.Fatal("native owner-enabled listing has no owner")
						}
						client := s3.New(s3NativeClient(r.clients, r.identity.AccessKeyID, r.identity.SecretAccessKey).Options(), func(o *s3.Options) { o.Region = fixture.Region })
						acl, err := client.GetBucketAcl(t.Context(), &s3.GetBucketAclInput{Bucket: aws.String(fixture.Prefix)})
						if err != nil || acl.Owner == nil {
							t.Fatalf("reading actual bucket owner: %+v, %v", acl, err)
						}
						r.bind(t, r.bindings, listed.Contents[0].Owner.Id, aws.ToString(acl.Owner.ID), true)
					}
					row := stepFunctionsTaskObservation{awsNativeObservation: captured.awsNativeObservation,
						StartedAt: time.UnixMilli(captured.Started), FinishedAt: time.UnixMilli(captured.Finished)}
					if row.Result.Code == "404" {
						// Bodyless HeadBucket failures are named by the SDK, while
						// the CLI reports their HTTP status as the error code.
						row.Result.Code, row.Result.HTTPStatus = "NotFound", 404
					}
					r.call(t, row)
				}) {
					return
				}
			}
		})
	}
}
