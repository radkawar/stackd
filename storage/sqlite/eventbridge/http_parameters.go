package eventbridge

import (
	"encoding/json"

	api "stackd/internal/awsapi/eventbridge"
)

var absentHTTPParameter = []byte("null")

func decodeHTTPParameters(present bool, headers, paths, query []byte) (*api.HttpParameters, error) {
	if !present {
		return nil, nil
	}
	p := &api.HttpParameters{}
	if err := json.Unmarshal(headers, &p.HeaderParameters); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(paths, &p.PathParameterValues); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(query, &p.QueryStringParameters); err != nil {
		return nil, err
	}
	return p, nil
}

func encodeHTTPParameters(p *api.HttpParameters) (headers, paths, query []byte, err error) {
	if p == nil {
		return absentHTTPParameter, absentHTTPParameter, absentHTTPParameter, nil
	}
	headers, err = json.Marshal(p.HeaderParameters)
	if err != nil {
		return nil, nil, nil, err
	}
	paths, err = json.Marshal(p.PathParameterValues)
	if err != nil {
		return nil, nil, nil, err
	}
	query, err = json.Marshal(p.QueryStringParameters)
	return headers, paths, query, err
}
