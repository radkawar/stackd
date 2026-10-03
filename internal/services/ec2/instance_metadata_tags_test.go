package ec2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	api "stackd/internal/awsapi/ec2"
)

// Replay real mutation requests through the tag/options owners and compare the
// resulting HTTP projection with the guest's converged observations. Native
// sample times bound this capture only; they are not an emulator delay schedule.
func TestNativeInstanceTagPublication(t *testing.T) {
	local := newMetadataTestInstance(t)
	var fixture struct {
		Owned  struct{ Instances []string }
		Phases []struct {
			Name    string
			Settled *struct {
				BootID string `json:"kernel_boot_id"`
				Sample int
			} `json:"settled_sample"`
		} `json:"tag_phases"`
		Samples []struct {
			BootID string `json:"kernel_boot_id"`
			Sample int
			HTTP   []metadataHTTPObservation
		}
	}
	raw, err := os.ReadFile("../../../testdata/aws/ec2/instances_tag_publication_handoff.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	observed := map[string][]metadataHTTPObservation{}
	for _, phase := range fixture.Phases {
		if phase.Settled == nil {
			t.Fatalf("native phase %s did not observe converged guest state", phase.Name)
		}
		for _, sample := range fixture.Samples {
			if sample.BootID == phase.Settled.BootID && sample.Sample == phase.Settled.Sample {
				observed[phase.Name] = sample.HTTP
			}
		}
	}
	var capture struct {
		Calls []struct {
			Label, Operation, Code string
			Input                  json.RawMessage
			Output                 struct {
				Reservations            []struct{ Instances []api.Instance }
				InstanceMetadataOptions *api.InstanceMetadataOptionsResponse
			}
		}
	}
	raw, err = os.ReadFile("../../../testdata/aws/ec2/instances_tag_publication.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.ReplaceAll(string(raw), fixture.Owned.Instances[0], local.record.Key.ID))
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	for _, call := range capture.Calls {
		if call.Label == "initial-before-instances" {
			initial := call.Output.Reservations[0].Instances[0]
			local.record.Data.Tags = initial.Tags
			local.record.Data.MetadataOptions = initial.MetadataOptions
		}
	}
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error { return tx.PutInstance(local.record) }); err != nil {
		t.Fatal(err)
	}
	token, err := newMetadataToken(local.record.MetadataTokenKey, local.clock.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range capture.Calls {
		if call.Code != "Success" {
			continue
		}
		switch call.Operation {
		case "CreateTags", "DeleteTags", "ModifyInstanceMetadataOptions":
			err := local.service.repository.Update(local.ctx, func(tx Transaction) error {
				switch call.Operation {
				case "CreateTags":
					var in api.CreateTagsRequest
					if err := json.Unmarshal(call.Input, &in); err != nil {
						return err
					}
					_, err := local.service.createTags(tx.Context(), tx, &in)
					return err
				case "DeleteTags":
					var in api.DeleteTagsRequest
					if err := json.Unmarshal(call.Input, &in); err != nil {
						return err
					}
					_, err := local.service.deleteTags(tx.Context(), tx, &in)
					return err
				case "ModifyInstanceMetadataOptions":
					var in api.ModifyInstanceMetadataOptionsRequest
					if err := json.Unmarshal(call.Input, &in); err != nil {
						return err
					}
					out, err := local.service.modifyInstanceMetadataOptions(tx.Context(), tx, &in)
					if err != nil {
						return err
					}
					if str(out.InstanceMetadataOptions.State) != str(call.Output.InstanceMetadataOptions.State) {
						return fmt.Errorf("metadata acceptance state = %s, native %s", str(out.InstanceMetadataOptions.State), str(call.Output.InstanceMetadataOptions.State))
					}
					return nil
				}
				return nil
			})
			if err != nil {
				t.Fatalf("%s: %v", call.Label, err)
			}
		}
		phase, found := strings.CutSuffix(call.Label, "-before-instances")
		if !found {
			continue
		}
		rows, ok := observed[phase]
		if !ok {
			t.Fatalf("no native guest rows for phase %s", phase)
		}
		t.Run(phase, func(t *testing.T) {
			for _, row := range rows {
				response := metadataHTTPRequest(t, local.service, local.record.Key, http.MethodGet, row.Path, token)
				if response.Code != row.Code {
					t.Fatalf("%s = HTTP %d, native %d", row.Path, response.Code, row.Code)
				}
				if row.Code != http.StatusOK {
					continue
				}
				if response.Header().Get("Content-Type") != row.Headers["Content-Type"] {
					t.Fatalf("%s content type = %q, native %q", row.Path, response.Header().Get("Content-Type"), row.Headers["Content-Type"])
				}
				path := strings.TrimSuffix(row.Path, "/")
				switch path {
				case "/latest/meta-data/tag-sets/instance":
					var got, want map[string]string
					if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal([]byte(*row.Body), &want); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("%s = %v, native %v", row.Path, got, want)
					}
				case "/latest/meta-data/tags/instance":
					got, want := strings.Split(response.Body.String(), "\n"), strings.Split(*row.Body, "\n")
					slices.Sort(got)
					slices.Sort(want)
					if !slices.Equal(got, want) {
						t.Fatalf("%s = %v, native %v", row.Path, got, want)
					}
				default:
					if response.Body.String() != *row.Body {
						t.Fatalf("%s = %q, native %q", row.Path, response.Body.String(), *row.Body)
					}
				}
			}
		})
	}
}

// The identity guest's independent capture also exercises metadata-option
// admission without changing its required-token policy. Use the preceding native
// instance snapshot as input, not the mutation's response or a guessed no-op rule.
func TestNativeInstanceMetadataOptionAcceptance(t *testing.T) {
	var capture struct {
		Calls []struct {
			Label, Operation, Code string
			Input                  json.RawMessage
			Output                 struct {
				Reservations            []struct{ Instances []api.Instance }
				InstanceMetadataOptions *api.InstanceMetadataOptionsResponse
			}
		}
	}
	raw, err := os.ReadFile("../../../testdata/aws/ec2/instance_identity_credentials.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	var before *api.Instance
	for _, call := range capture.Calls {
		if call.Code != "Success" {
			continue
		}
		if call.Operation == "DescribeInstances" && len(call.Output.Reservations) != 0 && len(call.Output.Reservations[0].Instances) != 0 {
			before = &call.Output.Reservations[0].Instances[0]
		}
		if call.Operation != "ModifyInstanceMetadataOptions" {
			continue
		}
		t.Run(call.Label, func(t *testing.T) {
			if before == nil {
				t.Fatal("native metadata modification has no preceding instance observation")
			}
			local := newMetadataTestInstance(t)
			local.record.Data.State = before.State
			local.record.Data.MetadataOptions = before.MetadataOptions
			local.record.Data.Tags = before.Tags
			if err := local.service.repository.Update(local.ctx, func(tx Transaction) error { return tx.PutInstance(local.record) }); err != nil {
				t.Fatal(err)
			}
			var in api.ModifyInstanceMetadataOptionsRequest
			if err := json.Unmarshal(call.Input, &in); err != nil {
				t.Fatal(err)
			}
			in.InstanceId = new(api.InstanceId(local.record.Key.ID))
			var out *api.ModifyInstanceMetadataOptionsResult
			if err := local.service.repository.Update(local.ctx, func(tx Transaction) error {
				var err error
				out, err = local.service.modifyInstanceMetadataOptions(tx.Context(), tx, &in)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(out.InstanceMetadataOptions, call.Output.InstanceMetadataOptions) {
				t.Fatalf("metadata acceptance = %+v, native %+v", out.InstanceMetadataOptions, call.Output.InstanceMetadataOptions)
			}
		})
	}
}
