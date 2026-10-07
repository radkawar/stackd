package sqs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

var queueNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func (s *Service) registerQueues() {
	register(s, "CreateQueue", true, s.createQueue)
	register(s, "GetQueueUrl", true, s.getQueueURL)
	register(s, "ListQueues", true, s.listQueues)
	register(s, "DeleteQueue", true, s.deleteQueue)
	register(s, "GetQueueAttributes", true, s.getAttributes)
	register(s, "SetQueueAttributes", true, s.setAttributes)
	register(s, "PurgeQueue", true, s.purgeQueue)
	register(s, "ListQueueTags", true, s.listTags)
	register(s, "TagQueue", true, s.tagQueue)
	register(s, "UntagQueue", true, s.untagQueue)
	register(s, "ListDeadLetterSourceQueues", true, s.listDeadLetterSources)
}
func (s *Service) createQueue(r *http.Request, in *api.CreateQueueInput) (*api.CreateQueueOutput, *awswire.Error) {
	name := value(in.QueueName)
	key := requestKey(r, name)
	config, err := s.configure(r.Context(), key, defaultConfig(), in.Attributes, true)
	if err != nil {
		return nil, err
	}
	plainName := name
	if config.fifo {
		plainName = strings.TrimSuffix(name, ".fifo")
		if plainName == name {
			return nil, failure("InvalidParameterValue", "FIFO queue names must end in .fifo.")
		}
	}
	if len(name) > 80 || !queueNamePattern.MatchString(plainName) {
		return nil, failure("InvalidParameterValue", "Invalid queue name.")
	}
	if err := validateTags(in.Tags); err != nil {
		return nil, err
	}
	if q := s.lookupQueue(key); q != nil {
		if owner := queueOwner(r.Context()); owner != "" && q.creationOwner != owner {
			return nil, failure("QueueNameExists", "A different queue incarnation already owns this name.")
		}
		// Compare attributes supplied on this request. Omitting attributes does not
		// reset existing settings; supplied tags do not mutate an existing queue.
		existing := q.attributes(s.now())
		requested := (&queue{key: key, config: config}).attributes(s.now())
		for attr := range in.Attributes {
			if attr == "RedrivePolicy" || attr == "RedriveAllowPolicy" {
				var a, b any
				_ = json.Unmarshal([]byte(existing[attr]), &a)
				_ = json.Unmarshal([]byte(requested[attr]), &b)
				if !reflect.DeepEqual(a, b) {
					return nil, failure("QueueNameExists", "A queue with this name already exists with different attributes.")
				}
				continue
			}
			if existing[attr] != requested[attr] {
				return nil, failure("QueueNameExists", "A queue with this name already exists with different attributes.")
			}
		}
		endpoint, wire := s.localURL(r, key)
		if wire != nil {
			return nil, wire
		}
		return &api.CreateQueueOutput{QueueUrl: str(endpoint)}, nil
	}
	now := s.now()
	if deleted := s.deletedAt(key); !deleted.IsZero() && now.Before(deleted.Add(time.Minute)) {
		return nil, failure("QueueDeletedRecently", "Wait 60 seconds after deleting a queue before recreating it.")
	}
	var secret [32]byte
	_, _ = rand.Read(secret[:])
	block, _ := aes.NewCipher(secret[:])
	aead, _ := cipher.NewGCM(block)
	q := &queue{key: key, id: identifier(), config: config, tags: cloneTags(in.Tags), created: now, modified: now, receipts: make(map[string]receipt), dedup: make(map[string]dedupRecord), attempts: make(map[string]receiveAttempt), secret: secret[:], messagesLoaded: true, queueRuntime: &queueRuntime{changed: make(chan struct{}), cipher: aead, keys: make(map[string]cachedKey)}}
	q.creationOwner = queueOwner(r.Context())
	s.queues[key] = q
	s.runtimes[q.id] = q.queueRuntime
	endpoint, wire := s.localURL(r, key)
	if wire != nil {
		return nil, wire
	}
	return &api.CreateQueueOutput{QueueUrl: str(endpoint)}, nil
}
func (s *Service) getQueueURL(r *http.Request, in *api.GetQueueUrlInput) (*api.GetQueueUrlOutput, *awswire.Error) {
	key := requestKey(r, value(in.QueueName))
	if owner := value(in.QueueOwnerAWSAccountId); owner != "" {
		key.account = owner
	}
	if s.lookupQueue(key) == nil {
		return nil, failure("QueueDoesNotExist", "The specified queue does not exist.")
	}
	endpoint, wire := s.localURL(r, key)
	if wire != nil {
		return nil, wire
	}
	return &api.GetQueueUrlOutput{QueueUrl: str(endpoint)}, nil
}
func (s *Service) deleteQueue(r *http.Request, in *api.DeleteQueueInput) (*api.DeleteQueueOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	s.removed[q.key] = true
	delete(s.queues, q.key)
	s.deleted[q.key] = s.now()
	q.notify()
	return &api.DeleteQueueOutput{}, nil
}
func (s *Service) getAttributes(r *http.Request, in *api.GetQueueAttributesInput) (*api.GetQueueAttributesOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	all := q.attributes(s.now())
	if q.config.policy != "" {
		rendered, err := s.renderPolicy(r.Context(), q)
		if err != nil {
			return nil, err
		}
		all["Policy"] = api.String(rendered)
	}
	out := make(api.QueueAttributeMap)
	for _, name := range in.AttributeNames {
		if name == "All" {
			return &api.GetQueueAttributesOutput{Attributes: all}, nil
		}
		if v, ok := all[name]; ok {
			out[name] = v
			continue
		}
		if !knownAttribute(name) {
			return nil, failure("InvalidAttributeName", "Unknown queue attribute: "+string(name))
		}
	}
	return &api.GetQueueAttributesOutput{Attributes: out}, nil
}
func knownAttribute(name api.QueueAttributeName) bool {
	return slices.Contains([]api.QueueAttributeName{"Policy", "VisibilityTimeout", "MaximumMessageSize", "MessageRetentionPeriod", "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible", "CreatedTimestamp", "LastModifiedTimestamp", "QueueArn", "ApproximateNumberOfMessagesDelayed", "DelaySeconds", "ReceiveMessageWaitTimeSeconds", "RedrivePolicy", "FifoQueue", "ContentBasedDeduplication", "KmsMasterKeyId", "KmsDataKeyReusePeriodSeconds", "DeduplicationScope", "FifoThroughputLimit", "RedriveAllowPolicy", "SqsManagedSseEnabled"}, name)
}
func (s *Service) setAttributes(r *http.Request, in *api.SetQueueAttributesInput) (*api.SetQueueAttributesOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	if _, changesPolicy := in.Attributes["Policy"]; changesPolicy {
		if owner := queuePolicyOwner(r.Context()); owner != "" {
			if q.policyOwner != "" && q.policyOwner != owner || q.policyOwner == "" && q.config.policy != "" {
				return nil, failure("AccessDenied", "The queue policy belongs to another resource incarnation.")
			}
		}
	}
	config, err := s.configure(r.Context(), q.key, q.config, in.Attributes, false)
	if err != nil {
		return nil, err
	}
	if q.config.fifo && config.delay != q.config.delay {
		for _, m := range q.messages {
			if m.receives == 0 {
				m.available = m.sent.Add(time.Duration(config.delay) * time.Second)
				m.ageStarted = m.available
			}
		}
	}
	q.config = config
	if _, changesPolicy := in.Attributes["Policy"]; changesPolicy {
		q.policyOwner = queuePolicyOwner(r.Context())
		if config.policy == "" {
			q.policyOwner = ""
		}
	}
	q.modified = s.now()
	s.prune(q, s.now())
	q.notify()
	return &api.SetQueueAttributesOutput{}, nil
}
func (s *Service) purgeQueue(r *http.Request, in *api.PurgeQueueInput) (*api.PurgeQueueOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	now := s.now()
	if !q.purged.IsZero() && now.Before(q.purged.Add(time.Minute)) {
		return nil, failure("PurgeQueueInProgress", "Only one PurgeQueue operation is allowed every 60 seconds.")
	}
	for _, m := range q.messages {
		m.generation++
	}
	q.messages = nil
	q.receipts = make(map[string]receipt)
	q.attempts = make(map[string]receiveAttempt)
	q.purged = now
	q.notify()
	return &api.PurgeQueueOutput{}, nil
}
func (s *Service) listTags(r *http.Request, in *api.ListQueueTagsInput) (*api.ListQueueTagsOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	return &api.ListQueueTagsOutput{Tags: cloneTags(q.tags)}, nil
}
func (s *Service) tagQueue(r *http.Request, in *api.TagQueueInput) (*api.TagQueueOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	tags := cloneTags(q.tags)
	maps.Copy(tags, in.Tags)
	if err := validateTags(tags); err != nil {
		return nil, err
	}
	q.tags = tags
	return &api.TagQueueOutput{}, nil
}
func (s *Service) untagQueue(r *http.Request, in *api.UntagQueueInput) (*api.UntagQueueOutput, *awswire.Error) {
	q, err := s.queueFor(r, value(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	for _, key := range in.TagKeys {
		delete(q.tags, key)
	}
	return &api.UntagQueueOutput{}, nil
}
