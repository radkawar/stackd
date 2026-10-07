package sqs

import (
	"crypto/cipher"
	"net/http"
	"net/url"
	"strings"
	"time"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type queueKey struct{ partition, account, region, name string }
type queueConfig struct {
	delay, maximumSize, retention, visibility, wait int
	fifo, contentDedup, managedSSE                  bool
	dedupScope, throughput                          string
	policy, kmsKey                                  string
	policyPrincipals                                map[string]string
	kmsReuse                                        int
	redrive                                         *redrivePolicy
	allow                                           redriveAllowPolicy
}
type redrivePolicy struct {
	DeadLetterTargetARN string `json:"deadLetterTargetArn"`
	MaxReceiveCount     int    `json:"maxReceiveCount"`
}
type redriveAllowPolicy struct {
	Permission string   `json:"redrivePermission"`
	Sources    []string `json:"sourceQueueArns,omitempty"`
}
type queue struct {
	key                                 queueKey
	id                                  string
	creationOwner                       string
	policyOwner                         string
	config                              queueConfig
	tags                                api.TagMap
	created, modified, purged           time.Time
	messages                            []*message
	receipts                            map[string]receipt
	dedup                               map[string]dedupRecord
	attempts                            map[string]receiveAttempt
	noisyGroups                         map[string]time.Time
	sequence                            uint64
	metricActiveUntil, nextMetricSample time.Time

	secret         []byte
	messagesLoaded bool
	*queueRuntime
}
type queueRuntime struct {
	changed chan struct{}
	cipher  cipher.AEAD
	keys    map[string]cachedKey
}
type payload struct {
	Body       string
	Attributes api.MessageBodyAttributeMap
	Trace      string
}
type message struct {
	id, group, dedup, sequence, sender           string
	data                                         []byte
	encrypted                                    bool
	keyARN                                       string
	dataKey                                      []byte
	bodyMD5                                      string
	sent, firstReceived, lastReceived, available time.Time
	retentionStarted                             time.Time
	receives                                     int
	ageStarted                                   time.Time
	queueReceives                                int
	receipt                                      string
	generation                                   uint64
	sourceARN                                    string
}
type receipt struct {
	message *message
	expires time.Time
}
type dedupRecord struct {
	id, sequence string
	expires      time.Time
}
type receiveAttempt struct {
	messages    []*message
	handles     []string
	generations []uint64
	expires     time.Time
}

func requestKey(r *http.Request, name string) queueKey {
	scope := awsctx.FromContext(r.Context())
	return queueKey{partition: scope.Partition, account: scope.AccountID, region: scope.Region, name: name}
}
func (k queueKey) arn() string {
	return "arn:" + k.partition + ":sqs:" + k.region + ":" + k.account + ":" + k.name
}
func (k queueKey) canonicalURL() string {
	suffix := "amazonaws.com"
	if k.partition == "aws-cn" {
		suffix = "amazonaws.com.cn"
	}
	return "https://sqs." + k.region + "." + suffix + "/" + k.account + "/" + k.name
}
func localURL(r *http.Request, k queueKey) string {
	if r.Host == "" {
		return k.canonicalURL()
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/" + k.account + "/" + k.name
}
func (s *Service) queueFor(r *http.Request, raw string) (*queue, *awswire.Error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, failure("InvalidAddress", "QueueUrl must be a valid queue URL.")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 {
		return nil, failure("InvalidAddress", "QueueUrl must contain an account and queue name.")
	}
	key := requestKey(r, parts[1])
	key.account = parts[0]
	q, wire := s.queueByKey(key)
	if wire != nil {
		return nil, wire
	}
	if wire := checkQueueOwner(r.Context(), q); wire != nil {
		return nil, wire
	}
	return q, nil
}

// queueByKey resolves message state for both URL and internal ARN commands.
func (s *Service) queueByKey(key queueKey) (*queue, *awswire.Error) {
	q := s.lookupQueue(key)
	if q == nil {
		return nil, failure("QueueDoesNotExist", "The specified queue does not exist.")
	}
	s.loadMessages(q)
	s.prune(q, s.now())
	return q, nil
}
func (q *queue) notify() { close(q.changed); q.changed = make(chan struct{}) }
func (s *Service) prune(q *queue, now time.Time) {
	kept := q.messages[:0]
	for _, m := range q.messages {
		if !now.Before(m.retentionStarted.Add(time.Duration(q.config.retention) * time.Second)) {
			m.generation++
			continue
		}
		kept = append(kept, m)
	}
	clear(q.messages[len(kept):])
	q.messages = kept
	for handle, rec := range q.receipts {
		if !now.Before(rec.expires) {
			delete(q.receipts, handle)
		}
	}
	for id, rec := range q.dedup {
		if !now.Before(rec.expires) {
			delete(q.dedup, id)
		}
	}
	for id, rec := range q.attempts {
		if !now.Before(rec.expires) {
			delete(q.attempts, id)
		}
	}
}
func (q *queue) contains(m *message) bool {
	for _, candidate := range q.messages {
		if candidate == m {
			return true
		}
	}
	return false
}
func (q *queue) remove(m *message) {
	for i, candidate := range q.messages {
		if candidate == m {
			copy(q.messages[i:], q.messages[i+1:])
			q.messages[len(q.messages)-1] = nil
			q.messages = q.messages[:len(q.messages)-1]
			m.generation++
			q.notify()
			return
		}
	}
}
