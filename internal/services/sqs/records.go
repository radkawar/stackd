package sqs

import (
	"crypto/aes"
	"crypto/cipher"
	"maps"
	"slices"
	"time"

	api "stackd/internal/awsapi/sqs"
)

func publicKey(k queueKey) QueueKey {
	return QueueKey{Partition: k.partition, Account: k.account, Region: k.region, Name: k.name}
}
func privateKey(k QueueKey) queueKey {
	return queueKey{partition: k.Partition, account: k.Account, region: k.Region, name: k.Name}
}
func queueRecord(q *queue) QueueRecord {
	c := q.config
	r := QueueRecord{Key: publicKey(q.key), ID: q.id, Created: q.created, Modified: q.modified, Purged: q.purged, Sequence: q.sequence, ManagedEncryptionKey: slices.Clone(q.secret), Configuration: QueueConfiguration{DelaySeconds: c.delay, MaximumMessageSize: c.maximumSize, RetentionSeconds: c.retention, VisibilitySeconds: c.visibility, WaitSeconds: c.wait, FIFO: c.fifo, ContentDeduplication: c.contentDedup, ManagedSSE: c.managedSSE, DeduplicationScope: c.dedupScope, Throughput: c.throughput, Policy: c.policy, PolicyPrincipals: maps.Clone(c.policyPrincipals), KMSKey: c.kmsKey, KMSReuseSeconds: c.kmsReuse, RedrivePermission: c.allow.Permission, RedriveSources: slices.Clone(c.allow.Sources)}}
	r.MetricActiveUntil, r.NextMetricSample = q.metricActiveUntil, q.nextMetricSample
	r.CreationOwner = q.creationOwner
	r.PolicyOwner = q.policyOwner
	if c.redrive != nil {
		r.Configuration.DeadLetterTargetARN = c.redrive.DeadLetterTargetARN
		r.Configuration.MaxReceiveCount = c.redrive.MaxReceiveCount
	}
	for k, v := range q.tags {
		r.Tags = append(r.Tags, QueueTag{Key: string(k), Value: string(v)})
	}
	slices.SortFunc(r.Tags, func(a, b QueueTag) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return 0
	})
	return r
}
func (s *Service) queueFromRecord(r QueueRecord) (*queue, error) {
	c := r.Configuration
	q := &queue{key: privateKey(r.Key), id: r.ID, created: r.Created, modified: r.Modified, purged: r.Purged, sequence: r.Sequence, secret: slices.Clone(r.ManagedEncryptionKey), tags: make(api.TagMap), config: queueConfig{delay: c.DelaySeconds, maximumSize: c.MaximumMessageSize, retention: c.RetentionSeconds, visibility: c.VisibilitySeconds, wait: c.WaitSeconds, fifo: c.FIFO, contentDedup: c.ContentDeduplication, managedSSE: c.ManagedSSE, dedupScope: c.DeduplicationScope, throughput: c.Throughput, policy: c.Policy, policyPrincipals: maps.Clone(c.PolicyPrincipals), kmsKey: c.KMSKey, kmsReuse: c.KMSReuseSeconds, allow: redriveAllowPolicy{Permission: c.RedrivePermission, Sources: slices.Clone(c.RedriveSources)}}}
	q.metricActiveUntil, q.nextMetricSample = r.MetricActiveUntil, r.NextMetricSample
	q.creationOwner = r.CreationOwner
	q.policyOwner = r.PolicyOwner
	if c.DeadLetterTargetARN != "" {
		q.config.redrive = &redrivePolicy{DeadLetterTargetARN: c.DeadLetterTargetARN, MaxReceiveCount: c.MaxReceiveCount}
	}
	for _, tag := range r.Tags {
		q.tags[api.TagKey(tag.Key)] = api.TagValue(tag.Value)
	}
	runtime := s.runtimes[r.ID]
	if runtime == nil {
		block, err := aes.NewCipher(q.secret)
		if err != nil {
			return nil, err
		}
		aead, _ := cipher.NewGCM(block)
		runtime = &queueRuntime{changed: make(chan struct{}), cipher: aead, keys: make(map[string]cachedKey)}
		s.runtimes[r.ID] = runtime
	}
	q.queueRuntime = runtime
	return q, nil
}
func messageRecord(m *message) MessageRecord {
	return MessageRecord{ID: m.id, Group: m.group, DeduplicationID: m.dedup, Sequence: m.sequence, Sender: m.sender, Data: slices.Clone(m.data), Encrypted: m.encrypted, KMSKeyARN: m.keyARN, EncryptedDataKey: slices.Clone(m.dataKey), BodyMD5: m.bodyMD5, Sent: m.sent, RetentionStarted: m.retentionStarted, AgeStarted: m.ageStarted, QueueReceives: m.queueReceives, FirstReceived: m.firstReceived, LastReceived: m.lastReceived, Available: m.available, Receives: m.receives, LatestReceipt: m.receipt, Generation: m.generation, SourceARN: m.sourceARN}
}
func messageFromRecord(r MessageRecord) *message {
	return &message{id: r.ID, group: r.Group, dedup: r.DeduplicationID, sequence: r.Sequence, sender: r.Sender, data: slices.Clone(r.Data), encrypted: r.Encrypted, keyARN: r.KMSKeyARN, dataKey: slices.Clone(r.EncryptedDataKey), bodyMD5: r.BodyMD5, sent: r.Sent, retentionStarted: r.RetentionStarted, ageStarted: r.AgeStarted, queueReceives: r.QueueReceives, firstReceived: r.FirstReceived, lastReceived: r.LastReceived, available: r.Available, receives: r.Receives, receipt: r.LatestReceipt, generation: r.Generation, sourceARN: r.SourceARN}
}
func queueMessages(q *queue) QueueMessages {
	var out QueueMessages
	for _, m := range q.messages {
		out.Messages = append(out.Messages, messageRecord(m))
	}
	for handle, rec := range q.receipts {
		m := rec.message
		out.Receipts = append(out.Receipts, ReceiptRecord{Handle: handle, MessageID: m.id, LatestReceipt: m.receipt, Expires: rec.expires, Available: m.available, LastReceived: m.lastReceived, Generation: m.generation})
	}
	for token, rec := range q.dedup {
		out.Deduplications = append(out.Deduplications, DeduplicationRecord{Token: token, MessageID: rec.id, Sequence: rec.sequence, Expires: rec.expires})
	}
	for token, attempt := range q.attempts {
		rec := ReceiveAttemptRecord{Token: token, Handles: slices.Clone(attempt.handles), Generations: slices.Clone(attempt.generations), Expires: attempt.expires}
		for _, m := range attempt.messages {
			rec.MessageIDs = append(rec.MessageIDs, m.id)
		}
		out.Attempts = append(out.Attempts, rec)
	}
	for group, until := range q.noisyGroups {
		out.NoisyGroups = append(out.NoisyGroups, NoisyGroupRecord{Group: group, InFlightUntil: until})
	}
	slices.SortFunc(out.NoisyGroups, func(a, b NoisyGroupRecord) int { return compareText(a.Group, b.Group) })
	slices.SortFunc(out.Receipts, func(a, b ReceiptRecord) int { return compareText(a.Handle, b.Handle) })
	slices.SortFunc(out.Deduplications, func(a, b DeduplicationRecord) int { return compareText(a.Token, b.Token) })
	slices.SortFunc(out.Attempts, func(a, b ReceiveAttemptRecord) int { return compareText(a.Token, b.Token) })
	return out
}
func compareText(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
func hydrateMessages(q *queue, records QueueMessages) {
	q.noisyGroups = make(map[string]time.Time, len(records.NoisyGroups))
	for _, r := range records.NoisyGroups {
		q.noisyGroups[r.Group] = r.InFlightUntil
	}
	byID := make(map[string]*message, len(records.Messages))
	q.messages = nil
	for _, r := range records.Messages {
		m := messageFromRecord(r)
		q.messages = append(q.messages, m)
		byID[m.id] = m
	}
	q.receipts = make(map[string]receipt, len(records.Receipts))
	for _, r := range records.Receipts {
		m := byID[r.MessageID]
		if m == nil {
			m = &message{id: r.MessageID, receipt: r.LatestReceipt, available: r.Available, lastReceived: r.LastReceived, generation: r.Generation}
			byID[r.MessageID] = m
		}
		q.receipts[r.Handle] = receipt{message: m, expires: r.Expires}
	}
	q.dedup = make(map[string]dedupRecord, len(records.Deduplications))
	for _, r := range records.Deduplications {
		q.dedup[r.Token] = dedupRecord{id: r.MessageID, sequence: r.Sequence, expires: r.Expires}
	}
	q.attempts = make(map[string]receiveAttempt, len(records.Attempts))
	for _, r := range records.Attempts {
		attempt := receiveAttempt{handles: slices.Clone(r.Handles), generations: slices.Clone(r.Generations), expires: r.Expires}
		for _, id := range r.MessageIDs {
			m := byID[id]
			if m == nil {
				m = &message{id: id}
			}
			attempt.messages = append(attempt.messages, m)
		}
		q.attempts[r.Token] = attempt
	}
	q.messagesLoaded = true
}
