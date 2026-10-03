package pipes

import (
	"encoding/json"

	api "stackd/internal/awsapi/pipes"
	"stackd/storage/sqlite/pipes/internal/sqlcgen"
)

func encodeEnrichmentHTTP(p *api.PipeEnrichmentHttpParameters, v *sqlcgen.PipesPipe) error {
	v.EnrichmentHttpPresent = p != nil
	v.EnrichmentHttpHeaders, v.EnrichmentHttpPaths, v.EnrichmentHttpQuery = "null", "null", "null"
	if p == nil {
		return nil
	}
	for _, field := range []struct {
		target *string
		value  any
	}{
		{&v.EnrichmentHttpHeaders, p.HeaderParameters},
		{&v.EnrichmentHttpPaths, p.PathParameterValues},
		{&v.EnrichmentHttpQuery, p.QueryStringParameters},
	} {
		encoded, err := json.Marshal(field.value)
		if err != nil {
			return err
		}
		*field.target = string(encoded)
	}
	return nil
}

func decodeEnrichmentHTTP(v sqlcgen.PipesPipe) (*api.PipeEnrichmentHttpParameters, error) {
	if !v.EnrichmentHttpPresent {
		return nil, nil
	}
	p := &api.PipeEnrichmentHttpParameters{}
	for _, field := range []struct {
		source string
		value  any
	}{
		{v.EnrichmentHttpHeaders, &p.HeaderParameters},
		{v.EnrichmentHttpPaths, &p.PathParameterValues},
		{v.EnrichmentHttpQuery, &p.QueryStringParameters},
	} {
		if err := json.Unmarshal([]byte(field.source), field.value); err != nil {
			return nil, err
		}
	}
	return p, nil
}
