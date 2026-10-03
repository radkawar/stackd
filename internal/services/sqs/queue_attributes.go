package sqs

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

func defaultConfig() queueConfig {
	return queueConfig{maximumSize: 1 << 20, retention: 345600, visibility: 30, managedSSE: true, dedupScope: "queue", throughput: "perQueue", allow: redriveAllowPolicy{Permission: "allowAll"}}
}

func (s *Service) configure(ctx context.Context, key queueKey, old queueConfig, attrs api.QueueAttributeMap, creating bool) (queueConfig, *awswire.Error) {
	next := old
	for name, raw := range attrs {
		v := string(raw)
		var target *int
		low, high := 0, 0
		switch name {
		case "DelaySeconds":
			target = &next.delay
			high = 900
		case "MaximumMessageSize":
			target = &next.maximumSize
			low = 1024
			high = 1 << 20
		case "MessageRetentionPeriod":
			target = &next.retention
			low = 60
			high = 1209600
		case "VisibilityTimeout":
			target = &next.visibility
			high = 43200
		case "ReceiveMessageWaitTimeSeconds":
			target = &next.wait
			high = 20
		case "KmsDataKeyReusePeriodSeconds":
			target = &next.kmsReuse
			low = 60
			high = 86400
		case "FifoQueue":
			if !creating {
				return old, failure("InvalidAttributeName", "FifoQueue can only be specified when creating a queue.")
			}
			if v != "true" && v != "false" {
				return old, invalidAttribute(name)
			}
			next.fifo = v == "true"
		case "ContentBasedDeduplication", "SqsManagedSseEnabled":
			if v != "true" && v != "false" {
				return old, invalidAttribute(name)
			}
			if name == "ContentBasedDeduplication" {
				next.contentDedup = v == "true"
			} else {
				next.managedSSE = v == "true"
			}
		case "DeduplicationScope":
			if v != "queue" && v != "messageGroup" {
				return old, invalidAttribute(name)
			}
			next.dedupScope = v
		case "FifoThroughputLimit":
			// TODO: Comeback enforce FIFO request-rate quotas, high-throughput regional limits, and batch-aware partition accounting.
			if v != "perQueue" && v != "perMessageGroupId" {
				return old, invalidAttribute(name)
			}
			next.throughput = v
		case "Policy":
			if v != "" {
				if len(v) > 8192 {
					return old, invalidAttribute(name)
				}
				if err := authorization.ValidateResourcePolicy([]byte(v)); err != nil {
					return old, invalidAttribute(name)
				}
			}
			bindings, err := s.bindPolicy(ctx, v)
			if err != nil {
				return old, err
			}
			next.policyPrincipals = bindings
			next.policy = v
		case "KmsMasterKeyId":
			if len(v) > 2048 {
				return old, invalidAttribute(name)
			}
			next.kmsKey = v
			if v != "" {
				next.managedSSE = false
			}
		case "RedrivePolicy":
			if v == "" {
				next.redrive = nil
				continue
			}
			var rawPolicy struct {
				ARN   string          `json:"deadLetterTargetArn"`
				Count json.RawMessage `json:"maxReceiveCount"`
			}
			if err := json.Unmarshal([]byte(v), &rawPolicy); err != nil {
				return old, invalidAttribute(name)
			}
			count, err := strconv.Atoi(strings.Trim(string(rawPolicy.Count), "\""))
			if err != nil || count < 1 || count > 1000 || rawPolicy.ARN == key.arn() {
				return old, invalidAttribute(name)
			}
			targetKey, ok := parseQueueARN(rawPolicy.ARN)
			if !ok || targetKey.partition != key.partition || targetKey.account != key.account || targetKey.region != key.region {
				return old, invalidAttribute(name)
			}
			next.redrive = &redrivePolicy{DeadLetterTargetARN: rawPolicy.ARN, MaxReceiveCount: count}
		case "RedriveAllowPolicy":
			if v == "" {
				next.allow = redriveAllowPolicy{Permission: "allowAll"}
				continue
			}
			var allow redriveAllowPolicy
			if err := json.Unmarshal([]byte(v), &allow); err != nil {
				return old, invalidAttribute(name)
			}
			switch allow.Permission {
			case "allowAll", "denyAll":
				if len(allow.Sources) != 0 {
					return old, invalidAttribute(name)
				}
			case "byQueue":
				if len(allow.Sources) == 0 || len(allow.Sources) > 10 {
					return old, invalidAttribute(name)
				}
				for _, arn := range allow.Sources {
					k, ok := parseQueueARN(arn)
					if !ok || k.partition != key.partition || k.account != key.account || k.region != key.region {
						return old, invalidAttribute(name)
					}
				}
			default:
				return old, invalidAttribute(name)
			}
			next.allow = allow
		default:
			return old, failure("InvalidAttributeName", "Unknown or read-only queue attribute: "+string(name))
		}
		if target != nil {
			n, err := strconv.Atoi(v)
			if err != nil || n < low || n > high {
				return old, invalidAttribute(name)
			}
			*target = n
		}
	}
	if next.kmsReuse == 0 {
		next.kmsReuse = 300
	}
	if attrs["SqsManagedSseEnabled"] == "true" {
		next.kmsKey = ""
	}
	if attrs["SqsManagedSseEnabled"] == "true" && attrs["KmsMasterKeyId"] != "" {
		return old, invalidAttribute("SqsManagedSseEnabled")
	}
	if !next.fifo {
		for _, name := range []api.QueueAttributeName{"ContentBasedDeduplication", "DeduplicationScope", "FifoThroughputLimit"} {
			if _, ok := attrs[name]; ok {
				return old, invalidAttribute(name)
			}
		}
	}
	if next.throughput == "perMessageGroupId" && next.dedupScope != "messageGroup" {
		return old, invalidAttribute("FifoThroughputLimit")
	}
	if next.redrive != nil {
		targetKey, _ := parseQueueARN(next.redrive.DeadLetterTargetARN)
		target := s.lookupQueue(targetKey)
		if target == nil || target.config.fifo != next.fifo {
			return old, invalidAttribute("RedrivePolicy")
		}
		if !target.config.allow.allows(key.arn()) {
			return old, invalidAttribute("RedrivePolicy")
		}
	}
	return next, nil
}
func invalidAttribute(name api.QueueAttributeName) *awswire.Error {
	return failure("InvalidAttributeValue", "Invalid value for the parameter "+string(name)+".")
}
func parseQueueARN(arn string) (queueKey, bool) {
	p := strings.Split(arn, ":")
	if len(p) != 6 || p[0] != "arn" || p[2] != "sqs" || p[1] == "" || p[3] == "" || len(p[4]) != 12 || p[5] == "" {
		return queueKey{}, false
	}
	return queueKey{partition: p[1], region: p[3], account: p[4], name: p[5]}, true
}
func (a redriveAllowPolicy) allows(arn string) bool {
	return a.Permission == "allowAll" || (a.Permission == "byQueue" && slices.Contains(a.Sources, arn))
}

func (q *queue) attributes(now time.Time) api.QueueAttributeMap {
	c := q.config
	out := api.QueueAttributeMap{"DelaySeconds": api.String(strconv.Itoa(c.delay)), "MaximumMessageSize": api.String(strconv.Itoa(c.maximumSize)), "MessageRetentionPeriod": api.String(strconv.Itoa(c.retention)), "VisibilityTimeout": api.String(strconv.Itoa(c.visibility)), "ReceiveMessageWaitTimeSeconds": api.String(strconv.Itoa(c.wait)), "QueueArn": api.String(q.key.arn()), "CreatedTimestamp": api.String(strconv.FormatInt(q.created.Unix(), 10)), "LastModifiedTimestamp": api.String(strconv.FormatInt(q.modified.Unix(), 10)), "SqsManagedSseEnabled": api.String(strconv.FormatBool(c.managedSSE))}
	var depth queueDepth
	for _, m := range q.messages {
		depth.add(m, now)
	}
	out["ApproximateNumberOfMessages"] = api.String(strconv.Itoa(depth.visible))
	out["ApproximateNumberOfMessagesNotVisible"] = api.String(strconv.Itoa(depth.inflight))
	out["ApproximateNumberOfMessagesDelayed"] = api.String(strconv.Itoa(depth.delayed))
	if c.fifo {
		out["FifoQueue"] = "true"
		out["ContentBasedDeduplication"] = api.String(strconv.FormatBool(c.contentDedup))
		out["DeduplicationScope"] = api.String(c.dedupScope)
		out["FifoThroughputLimit"] = api.String(c.throughput)
	}
	if c.policy != "" {
		out["Policy"] = api.String(c.policy)
	}
	if c.kmsKey != "" {
		out["KmsMasterKeyId"] = api.String(c.kmsKey)
		out["KmsDataKeyReusePeriodSeconds"] = api.String(strconv.Itoa(c.kmsReuse))
	}
	if c.redrive != nil {
		b, _ := json.Marshal(c.redrive)
		out["RedrivePolicy"] = api.String(b)
	}
	if c.allow.Permission != "allowAll" {
		b, _ := json.Marshal(c.allow)
		out["RedriveAllowPolicy"] = api.String(b)
	}
	return out
}
func validateTags(tags api.TagMap) *awswire.Error {
	if len(tags) > 50 {
		return failure("TooManyTags", "A queue may have at most 50 tags.")
	}
	for k, v := range tags {
		if len(k) == 0 || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(string(k)), "aws:") {
			return failure("InvalidParameterValue", "Invalid queue tag.")
		}
	}
	return nil
}
func cloneTags(tags api.TagMap) api.TagMap {
	out := maps.Clone(tags)
	if out == nil {
		out = make(api.TagMap)
	}
	return out
}
