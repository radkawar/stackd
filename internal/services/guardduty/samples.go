package guardduty

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awscatalog"
)

// Native-generated explicit sample fixtures, not detections of customer activity.
//
//go:embed sample_templates.json.gz
var sampleCorpus []byte

type sampleTemplate struct {
	revision string
	finding  api.Finding
}
type sampleCatalogue struct {
	byRevision map[string]sampleTemplate
	byType     map[string][]sampleTemplate
	ordered    []sampleTemplate
}

var samples = sync.OnceValues(loadSampleCatalogue)

func loadSampleCatalogue() (*sampleCatalogue, error) {
	reader, err := gzip.NewReader(bytes.NewReader(sampleCorpus))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	var corpus struct {
		Schema    int `json:"schema"`
		Templates []struct {
			Revision string          `json:"revision"`
			Finding  json.RawMessage `json:"finding"`
		} `json:"templates"`
	}
	if err := json.NewDecoder(reader).Decode(&corpus); err != nil {
		return nil, err
	}
	if corpus.Schema != 1 {
		return nil, fmt.Errorf("unsupported GuardDuty sample corpus schema %d", corpus.Schema)
	}
	out := &sampleCatalogue{byRevision: map[string]sampleTemplate{}, byType: map[string][]sampleTemplate{}}
	model, _ := awscatalog.LookupService("guardduty")
	for _, row := range corpus.Templates {
		var finding api.Finding
		if err := awsapi.BindJSON(model, "com.amazonaws.guardduty#Finding", row.Finding, &finding); err != nil {
			return nil, fmt.Errorf("decode GuardDuty sample %s: %w", row.Revision, err)
		}
		if finding.Service == nil || finding.Service.AdditionalInfo == nil {
			return nil, fmt.Errorf("GuardDuty sample %s has no sample evidence", row.Revision)
		}
		var info struct {
			Sample bool `json:"sample"`
		}
		if err := json.Unmarshal([]byte(value(finding.Service.AdditionalInfo.Value)), &info); err != nil || !info.Sample {
			return nil, fmt.Errorf("GuardDuty corpus contains non-sample finding %s", row.Revision)
		}
		t := sampleTemplate{revision: row.Revision, finding: finding}
		out.byRevision[t.revision] = t
		out.byType[value(finding.Type)] = append(out.byType[value(finding.Type)], t)
		out.ordered = append(out.ordered, t)
	}
	return out, nil
}
func findingOutput(v Finding) (api.Finding, error) {
	if v.Observation.Type != "" {
		if v.Observation.Kubernetes != nil {
			out, err := kubernetesFindingOutput(v)
			if err != nil {
				return api.Finding{}, err
			}
			return *out, nil
		}
		return observedFindingOutput(v), nil
	}
	catalogue, err := samples()
	if err != nil {
		return api.Finding{}, err
	}
	template, ok := catalogue.byRevision[v.SampleRevision]
	if !ok || value(template.finding.Type) != v.SampleType {
		return api.Finding{}, fmt.Errorf("retained GuardDuty sample revision is unavailable: %s", v.SampleRevision)
	}
	out := api.CloneFinding(template.finding)
	// Rebind only the capture's owning identity. Other fictional resource regions,
	// accounts, names and threat details remain the native sample fixture values.
	replace := strings.NewReplacer(value(out.AccountId), v.AccountID, value(out.Service.DetectorId), v.DetectorID, value(out.Id), v.ID)
	mapFindingStrings(&out, replace.Replace)
	text(&out.AccountId, v.AccountID)
	text(&out.Id, v.ID)
	text(&out.Region, v.Region)
	text(&out.Partition, v.Partition)
	text(&out.Arn, detectorARN(v.Scope, v.DetectorID)+"/finding/"+v.ID)
	text(&out.CreatedAt, v.Created.UTC().Format(time.RFC3339Nano))
	text(&out.UpdatedAt, v.Updated.UTC().Format(time.RFC3339Nano))
	text(&out.Service.DetectorId, v.DetectorID)
	text(&out.Service.EventFirstSeen, v.Created.UTC().Format(time.RFC3339Nano))
	text(&out.Service.EventLastSeen, v.Updated.UTC().Format(time.RFC3339Nano))
	count := api.Integer(v.Count)
	out.Service.Count = &count
	boolean(&out.Service.Archived, v.Archived)
	out.Service.UserFeedback = nil
	if v.Feedback != "" {
		text(&out.Service.UserFeedback, v.Feedback)
	}
	return out, nil
}
