package sns

import (
	"encoding/json"
	"math"
	"strings"
	"time"

	"stackd/internal/awswire"
)

type httpRetryPolicy struct {
	MinDelay       int    `json:"minDelayTarget"`
	MaxDelay       int    `json:"maxDelayTarget"`
	Retries        int    `json:"numRetries"`
	MaxRetries     int    `json:"numMaxDelayRetries"`
	NoDelayRetries int    `json:"numNoDelayRetries"`
	MinRetries     int    `json:"numMinDelayRetries"`
	Backoff        string `json:"backoffFunction"`
}
type httpRequestPolicy struct {
	ContentType string `json:"headerContentType"`
}
type httpThrottlePolicy struct {
	Rate int `json:"maxReceivesPerSecond"`
}
type httpDeliveryPolicy struct {
	Retry    *httpRetryPolicy    `json:"healthyRetryPolicy,omitempty"`
	Throttle *httpThrottlePolicy `json:"throttlePolicy,omitempty"`
	Request  *httpRequestPolicy  `json:"requestPolicy,omitempty"`
}
type httpTopicPolicy struct {
	HTTP struct {
		Retry            *httpRetryPolicy    `json:"defaultHealthyRetryPolicy,omitempty"`
		Throttle         *httpThrottlePolicy `json:"defaultThrottlePolicy,omitempty"`
		Request          *httpRequestPolicy  `json:"defaultRequestPolicy,omitempty"`
		DisableOverrides bool                `json:"disableSubscriptionOverrides"`
	} `json:"http"`
}

func defaultHTTPPolicy() httpDeliveryPolicy {
	return httpDeliveryPolicy{Retry: &httpRetryPolicy{MinDelay: 20, MaxDelay: 20, Retries: 3, Backoff: "linear"}, Request: &httpRequestPolicy{ContentType: "text/plain; charset=UTF-8"}}
}
func effectiveHTTPPolicy(topic TopicRecord, sub SubscriptionRecord) httpDeliveryPolicy {
	result := defaultHTTPPolicy()
	var top httpTopicPolicy
	_ = json.Unmarshal([]byte(topic.DeliveryPolicy), &top)
	if top.HTTP.Retry != nil {
		result.Retry = top.HTTP.Retry
	}
	if top.HTTP.Throttle != nil {
		result.Throttle = top.HTTP.Throttle
	}
	if top.HTTP.Request != nil {
		result.Request = top.HTTP.Request
	}
	if !top.HTTP.DisableOverrides {
		var own httpDeliveryPolicy
		_ = json.Unmarshal([]byte(sub.DeliveryPolicy), &own)
		if own.Retry != nil {
			result.Retry = own.Retry
		}
		if own.Throttle != nil {
			result.Throttle = own.Throttle
		}
		if own.Request != nil {
			result.Request = own.Request
		}
	}
	return result
}
func validateHTTPPolicy(document string, raw, topic bool) (string, *awswire.Error) {
	if document == "" {
		return "", nil
	}
	var policy httpDeliveryPolicy
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.DisallowUnknownFields()
	if topic {
		var top httpTopicPolicy
		if err := decoder.Decode(&top); err != nil {
			return "", failure("InvalidParameter", "Invalid parameter: DeliveryPolicy")
		}
		policy = httpDeliveryPolicy{Retry: top.HTTP.Retry, Throttle: top.HTTP.Throttle, Request: top.HTTP.Request}
	} else if err := decoder.Decode(&policy); err != nil {
		return "", failure("InvalidParameter", "Invalid parameter: DeliveryPolicy")
	}
	if retry := policy.Retry; retry != nil {
		if retry.MinDelay < 1 || retry.MaxDelay < retry.MinDelay || retry.MaxDelay > 3600 || retry.Retries < 0 || retry.Retries > 100 || retry.NoDelayRetries < 0 || retry.MinRetries < 0 || retry.MaxRetries < 0 || retry.NoDelayRetries+retry.MinRetries+retry.MaxRetries > retry.Retries {
			return "", failure("InvalidParameter", "Invalid parameter: DeliveryPolicy healthyRetryPolicy")
		}
		switch retry.Backoff {
		case "linear", "arithmetic", "geometric", "exponential":
		default:
			return "", failure("InvalidParameter", "Invalid parameter: DeliveryPolicy backoffFunction")
		}
		var total time.Duration
		for attempt := 1; attempt <= retry.Retries; attempt++ {
			total += httpRetryDelay(*retry, attempt)
		}
		if total > time.Hour {
			return "", failure("InvalidParameter", "Invalid parameter: DeliveryPolicy total retry time exceeds 3600 seconds")
		}
	}
	if policy.Throttle != nil && policy.Throttle.Rate < 1 {
		return "", failure("InvalidParameter", "Invalid parameter: DeliveryPolicy maxReceivesPerSecond")
	}
	if policy.Request != nil {
		valid := policy.Request.ContentType == "application/json" || policy.Request.ContentType == "text/plain"
		if raw && !topic {
			for _, candidate := range []string{"text/css", "text/csv", "text/html", "text/xml", "application/atom+xml", "application/octet-stream", "application/soap+xml", "application/x-www-form-urlencoded", "application/xhtml+xml", "application/xml"} {
				valid = valid || policy.Request.ContentType == candidate
			}
		}
		if !valid {
			return "", failure("InvalidParameter", "Invalid parameter: DeliveryPolicy headerContentType")
		}
	}
	var object any
	if json.Unmarshal([]byte(document), &object) != nil || object == nil {
		return "", failure("InvalidParameter", "Invalid parameter: DeliveryPolicy")
	}
	encoded, _ := json.Marshal(object)
	return string(encoded), nil
}

// Service time owns retry deadlines. These bounded curves do not claim AWS's
// randomized dispatch times; retained attempts and the policy budget are exact.
// TODO: Comeback calibrate HTTP retry jitter, throttle bursts and configuration propagation against longer native windows.
func httpRetryDelay(policy httpRetryPolicy, attempt int) time.Duration {
	if attempt <= policy.NoDelayRetries {
		return 0
	}
	attempt -= policy.NoDelayRetries
	if attempt <= policy.MinRetries {
		return time.Duration(policy.MinDelay) * time.Second
	}
	attempt -= policy.MinRetries
	count := policy.Retries - policy.NoDelayRetries - policy.MinRetries - policy.MaxRetries
	if attempt > count || count <= 1 {
		return time.Duration(policy.MaxDelay) * time.Second
	}
	position := float64(attempt-1) / float64(count-1)
	lo, hi := float64(policy.MinDelay), float64(policy.MaxDelay)
	delay := lo + (hi-lo)*position
	switch policy.Backoff {
	case "arithmetic":
		delay = lo + (hi-lo)*position*position
	case "geometric":
		delay = lo * math.Pow(hi/lo, position)
	case "exponential":
		delay = math.Min(hi, lo*math.Pow(2, float64(attempt-1)))
	}
	return time.Duration(delay * float64(time.Second))
}

func httpEffectivePolicyJSON(policy httpDeliveryPolicy) string {
	document := struct {
		Retry      *httpRetryPolicy    `json:"healthyRetryPolicy"`
		Sickly     any                 `json:"sicklyRetryPolicy"`
		Throttle   *httpThrottlePolicy `json:"throttlePolicy"`
		Request    *httpRequestPolicy  `json:"requestPolicy"`
		Guaranteed bool                `json:"guaranteed"`
	}{Retry: policy.Retry, Throttle: policy.Throttle, Request: policy.Request}
	encoded, _ := json.Marshal(document)
	return string(encoded)
}

func effectiveHTTPTopicPolicyJSON(topic TopicRecord) string {
	var document httpTopicPolicy
	_ = json.Unmarshal([]byte(topic.DeliveryPolicy), &document)
	policy := effectiveHTTPPolicy(topic, SubscriptionRecord{})
	document.HTTP.Retry, document.HTTP.Throttle, document.HTTP.Request = policy.Retry, policy.Throttle, policy.Request
	encoded, _ := json.Marshal(document)
	return string(encoded)
}
