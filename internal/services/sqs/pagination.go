package sqs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

type pageToken struct{ Scope, Filter, After string }

func (s *Service) queuePage(r *http.Request, filter string, keys []queueKey, max *api.BoxedInteger, token *api.Token) (api.QueueUrlList, *api.Token, *awswire.Error) {
	limit := 1000
	if max != nil {
		limit = int(*max)
		if limit < 1 || limit > 1000 {
			return nil, nil, failure("InvalidParameterValue", "MaxResults must be between 1 and 1000.")
		}
	}
	scope := requestKey(r, "").arn()
	after := ""
	if value(token) != "" {
		parts := strings.Split(value(token), ".")
		if len(parts) != 2 {
			return nil, nil, failure("InvalidParameterValue", "Invalid pagination token.")
		}
		data, e1 := base64.RawURLEncoding.DecodeString(parts[0])
		sig, e2 := base64.RawURLEncoding.DecodeString(parts[1])
		mac := hmac.New(sha256.New, s.tokenKey[:])
		_, _ = mac.Write(data)
		var decoded pageToken
		if e1 != nil || e2 != nil || !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(data, &decoded) != nil || decoded.Scope != scope || decoded.Filter != filter {
			return nil, nil, failure("InvalidParameterValue", "Invalid pagination token.")
		}
		after = decoded.After
	}
	slices.SortFunc(keys, func(a, b queueKey) int { return strings.Compare(a.name, b.name) })
	out := api.QueueUrlList{}
	var next *api.Token
	for _, key := range keys {
		if key.name <= after {
			continue
		}
		if len(out) == limit {
			if max != nil {
				payload, _ := json.Marshal(pageToken{Scope: scope, Filter: filter, After: after})
				mac := hmac.New(sha256.New, s.tokenKey[:])
				_, _ = mac.Write(payload)
				next = ptr(api.Token(base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))))
			}
			break
		}
		endpoint, wire := s.localURL(r, key)
		if wire != nil {
			return nil, nil, wire
		}
		out = append(out, api.String(endpoint))
		after = key.name
	}
	return out, next, nil
}
func (s *Service) listQueues(r *http.Request, in *api.ListQueuesInput) (*api.ListQueuesOutput, *awswire.Error) {
	key := requestKey(r, "")
	prefix := value(in.QueueNamePrefix)
	var keys []queueKey
	for candidate := range s.allQueues() {
		if candidate.partition == key.partition && candidate.account == key.account && candidate.region == key.region && strings.HasPrefix(candidate.name, prefix) {
			keys = append(keys, candidate)
		}
	}
	urls, next, err := s.queuePage(r, "ListQueues:"+prefix, keys, in.MaxResults, in.NextToken)
	if err != nil {
		return nil, err
	}
	return &api.ListQueuesOutput{QueueUrls: urls, NextToken: next}, nil
}
func (s *Service) listDeadLetterSources(r *http.Request, in *api.ListDeadLetterSourceQueuesInput) (*api.ListDeadLetterSourceQueuesOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	var keys []queueKey
	for key, candidate := range s.allQueues() {
		if candidate.config.redrive != nil && candidate.config.redrive.DeadLetterTargetARN == q.key.arn() {
			keys = append(keys, key)
		}
	}
	urls, next, err := s.queuePage(r, "ListDeadLetterSourceQueues:"+q.id, keys, in.MaxResults, in.NextToken)
	if err != nil {
		return nil, err
	}
	return &api.ListDeadLetterSourceQueuesOutput{QueueUrls: urls, NextToken: next}, nil
}
