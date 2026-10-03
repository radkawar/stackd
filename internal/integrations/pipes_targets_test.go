package integrations

import (
	"testing"

	api "stackd/internal/awsapi/pipes"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/lambda"
	"stackd/internal/services/pipes"
)

func TestPipesEnrichmentHTTPRequiresDestinationService(t *testing.T) {
	// A qualified Lambda named "events" contains ":events:" in its resource,
	// but must not be admitted as HTTP enrichment with silently ignored fields.
	adapter := &PipesTargets{
		APIDestinations: new(eventbridge.Service),
		Functions:       new(lambda.Service),
	}
	pipe := pipes.PipeRecord{
		Key:            pipes.Key{Scope: pipes.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "enrichment"},
		TargetARN:      "arn:aws:events:us-east-1:111111111111:api-destination/target/id",
		EnrichmentARN:  "arn:aws:lambda:us-east-1:111111111111:function:events:release",
		Source:         pipes.SourceSettings{BatchSize: 1},
		EnrichmentHTTP: &api.PipeEnrichmentHttpParameters{HeaderParameters: api.HeaderParametersMap{"X-Value": "retained"}},
	}
	if rejected := adapter.Validate(t.Context(), pipe); rejected == nil || rejected.Code != "ValidationException" {
		t.Fatalf("non-HTTP enrichment accepted HTTP parameters: %v", rejected)
	}
}
