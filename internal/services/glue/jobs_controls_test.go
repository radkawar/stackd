package glue

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type jobControlAuthorizer struct{}

func (jobControlAuthorizer) Authorize(context.Context, authorization.Request) *awswire.Error {
	return nil
}

// The owned native controls capture distinguishes exact duplicate admission,
// changed-definition conflicts, and replacement (not patch) update semantics.
func TestNativeJobDefinitionTransitions(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/glue/controls_native.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Label, Operation string
			Input            json.RawMessage
			Result           struct{ Code string }
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	s := &Service{repository: NewMemoryRepository(nil), clock: clock.NewManual(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)), authorizer: jobControlAuthorizer{}}
	metadata := awsctx.FromContext(t.Context())
	metadata.Partition, metadata.AccountID, metadata.Region = "aws", "123456789012", "us-east-1"
	ctx := awsctx.WithMetadata(t.Context(), metadata)
	var key ResourceKey
	for _, observation := range fixture.Observations {
		switch observation.Label {
		case "create-job-no-run", "create-job-exact-duplicate", "create-job-changed-description", "create-job-changed-script", "update-job-omitted-fields":
		default:
			continue
		}
		t.Run(observation.Label, func(t *testing.T) {
			err := s.repository.Update(ctx, func(tx Transaction) error {
				if observation.Operation == "create-job" {
					decoded, err := api.DecodeRequest("CreateJob", awsapi.Request{JSON: observation.Input})
					if err != nil {
						return err
					}
					in := decoded.Input.(*api.CreateJobInput)
					key = ResourceKey{scopeFor(ctx), value(in.Name)}
					_, err = s.createJob(tx.Context(), tx, in)
					return err
				}
				decoded, err := api.DecodeRequest("UpdateJob", awsapi.Request{JSON: observation.Input})
				if err != nil {
					return err
				}
				_, err = s.updateJob(tx.Context(), tx, decoded.Input.(*api.UpdateJobInput))
				return err
			})
			code := "Success"
			if err != nil {
				var wire *awswire.Error
				if !errors.As(err, &wire) {
					t.Fatal(err)
				}
				code = wire.Code
			}
			if code != observation.Result.Code {
				t.Fatalf("native code %s; local %s", observation.Result.Code, code)
			}
		})
	}
	if err := s.repository.View(ctx, func(tx Reader) error {
		job, err := tx.GetJob(key)
		if err != nil {
			return err
		}
		if len(job.DefaultArguments) != 0 || job.Description != "" || job.MaxConcurrentRuns != 1 {
			t.Fatalf("UpdateJob incorrectly patched omitted fields: %+v", job)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
