package sns

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"stackd/storage/memory"
)

type memoryState struct {
	topics            map[TopicKey]TopicRecord
	subscriptions     map[SubscriptionKey]SubscriptionRecord
	messages          map[MessageKey]MessageRecord
	deliveries        map[string]DeliveryRecord
	messageReferences map[MessageKey]int
	metricSamples     map[MetricPublicationKey]map[metricSampleKey]int64
	signingKey        *SigningKeyRecord
	deduplication     map[DeduplicationKey]DeduplicationRecord
	deliveryTails     map[deliveryGroupKey]string
	confirmations     map[string]ConfirmationRecord
	archiveEntries    map[MessageKey]ArchiveEntry
}

type deliveryGroupKey struct {
	subscription SubscriptionKey
	group        string
}

type metricSampleKey struct {
	name  string
	value int64
}

type MemoryRepository struct{ store *memory.Store[memoryState] }

func NewMemoryRepository(domain *memory.Domain) *MemoryRepository {
	initial := memoryState{topics: map[TopicKey]TopicRecord{}, subscriptions: map[SubscriptionKey]SubscriptionRecord{}, messages: map[MessageKey]MessageRecord{}, deliveries: map[string]DeliveryRecord{}, messageReferences: map[MessageKey]int{}, metricSamples: map[MetricPublicationKey]map[metricSampleKey]int64{}}
	initial.deduplication = make(map[DeduplicationKey]DeduplicationRecord)
	initial.deliveryTails = make(map[deliveryGroupKey]string)
	initial.confirmations = make(map[string]ConfirmationRecord)
	initial.archiveEntries = make(map[MessageKey]ArchiveEntry)
	return &MemoryRepository{memory.New(domain, initial, func(v memoryState) memoryState {
		groups := maps.Clone(v.metricSamples)
		for key, group := range groups {
			groups[key] = maps.Clone(group)
		}
		return memoryState{maps.Clone(v.topics), maps.Clone(v.subscriptions), maps.Clone(v.messages), maps.Clone(v.deliveries), maps.Clone(v.messageReferences), groups, v.signingKey, maps.Clone(v.deduplication), maps.Clone(v.deliveryTails), maps.Clone(v.confirmations), maps.Clone(v.archiveEntries)}
	})}
}

func (m *MemoryRepository) View(ctx context.Context, fn func(Reader) error) error {
	return m.store.View(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryReader{s, tx}) })
}
func (m *MemoryRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Update(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}
func (m *MemoryRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return m.store.Attempt(ctx, func(s *memoryState, tx *memory.Transaction) error { return fn(memoryWriter{memoryReader{s, tx}}) })
}

type memoryReader struct {
	s  *memoryState
	tx *memory.Transaction
}
type memoryWriter struct{ memoryReader }

func (r memoryReader) Context() context.Context { return r.tx.Context() }

func (r memoryReader) Topic(k TopicKey) (TopicRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return TopicRecord{}, err
	}
	v, ok := r.s.topics[k]
	if !ok {
		return TopicRecord{}, ErrNotFound
	}
	return cloneTopic(v), nil
}
func (r memoryReader) Topics(q TopicQuery) ([]TopicRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []TopicRecord{}
	for k, v := range r.s.topics {
		if k.Scope == q.Scope && k.Name > q.After {
			out = append(out, cloneTopic(v))
		}
	}
	slices.SortFunc(out, func(a, b TopicRecord) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (r memoryReader) TopicCount(scope Scope) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	var n int64
	for k := range r.s.topics {
		if k.Scope == scope {
			n++
		}
	}
	return n, nil
}
func (r memoryReader) Subscription(k SubscriptionKey) (SubscriptionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SubscriptionRecord{}, err
	}
	v, ok := r.s.subscriptions[k]
	if !ok {
		return SubscriptionRecord{}, ErrNotFound
	}
	return cloneSubscription(v), nil
}
func (r memoryReader) SubscriptionByEndpoint(topicID, protocol, endpoint string) (SubscriptionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SubscriptionRecord{}, err
	}
	for _, v := range r.s.subscriptions {
		if v.TopicID == topicID && v.Protocol == protocol && v.Endpoint == endpoint {
			return cloneSubscription(v), nil
		}
	}
	return SubscriptionRecord{}, ErrNotFound
}

func (r memoryReader) Confirmation(token string) (ConfirmationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ConfirmationRecord{}, err
	}
	v, ok := r.s.confirmations[token]
	if !ok {
		return ConfirmationRecord{}, ErrNotFound
	}
	return v, nil
}

func (w memoryWriter) PutConfirmation(v ConfirmationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.confirmations[v.Token] = v
	return nil
}
func (w memoryWriter) DeleteExpiredConfirmations(now time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for token, confirmation := range w.s.confirmations {
		if !confirmation.Expires.After(now) {
			delete(w.s.confirmations, token)
		}
	}
	return nil
}
func (r memoryReader) SubscriptionsByTopic(q TopicSubscriptionQuery) ([]SubscriptionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SubscriptionRecord{}
	for k, v := range r.s.subscriptions {
		if k.Topic == q.Topic && (q.TopicID == "" || v.TopicID == q.TopicID) && k.ID > q.After {
			out = append(out, cloneSubscription(v))
		}
	}
	slices.SortFunc(out, func(a, b SubscriptionRecord) int { return strings.Compare(a.Key.ID, b.Key.ID) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (r memoryReader) SubscriptionsByOwner(q OwnerSubscriptionQuery) ([]SubscriptionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []SubscriptionRecord{}
	for k, v := range r.s.subscriptions {
		if k.Topic.Partition != q.Partition || k.Topic.Region != q.Region || v.Owner != q.AccountID || k.ARN() <= q.AfterARN {
			continue
		}
		if topic, ok := r.s.topics[k.Topic]; ok && topic.ID == v.TopicID {
			out = append(out, cloneSubscription(v))
		}
	}
	slices.SortFunc(out, func(a, b SubscriptionRecord) int { return strings.Compare(a.Key.ARN(), b.Key.ARN()) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (r memoryReader) SubscriptionCount(topicID string) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	var n int64
	for _, v := range r.s.subscriptions {
		if v.TopicID == topicID {
			n++
		}
	}
	return n, nil
}
func (r memoryReader) FilterPolicyCount(scope Scope, topicID string) (int64, error) {
	if err := r.tx.Check(false); err != nil {
		return 0, err
	}
	var n int64
	for k, v := range r.s.subscriptions {
		if k.Topic.Partition != scope.Partition || k.Topic.Region != scope.Region || v.FilterPolicy == "" || v.FilterPolicy == "{}" {
			continue
		}
		if topicID != "" && v.TopicID == topicID || topicID == "" && v.Owner == scope.AccountID {
			n++
		}
	}
	return n, nil
}
func (r memoryReader) Message(k MessageKey) (MessageRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return MessageRecord{}, err
	}
	v, ok := r.s.messages[k]
	if !ok {
		return MessageRecord{}, ErrNotFound
	}
	return cloneMessage(v), nil
}
func (r memoryReader) Delivery(id string) (DeliveryRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DeliveryRecord{}, err
	}
	v, ok := r.s.deliveries[id]
	if !ok {
		return DeliveryRecord{}, ErrNotFound
	}
	return v, nil
}
func (r memoryReader) NextDelivery() (scheduler.Job, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return scheduler.Job{}, false, err
	}
	var next scheduler.Job
	found := false
	for _, v := range r.s.deliveries {
		if previous, exists := r.s.deliveries[v.FIFOPrevious]; exists && !previous.DeadLetter && !v.DeadLetter {
			continue
		}
		if !found || v.Due.Before(next.Due) || v.Due.Equal(next.Due) && v.ID < next.Key {
			next = scheduler.Job{Key: v.ID, Version: v.Version, Due: v.Due}
			found = true
		}
	}
	return next, found, nil
}
func (r memoryReader) NextSubscriptionDeletion() (scheduler.Job, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return scheduler.Job{}, false, err
	}
	var next scheduler.Job
	found := false
	for k, v := range r.s.subscriptions {
		if v.DeletionDue == nil {
			continue
		}
		arn := k.ARN()
		if !found || v.DeletionDue.Before(next.Due) || v.DeletionDue.Equal(next.Due) && arn < next.Key {
			next = scheduler.Job{Key: arn, Version: v.Version, Due: *v.DeletionDue}
			found = true
		}
	}
	return next, found, nil
}
func (r memoryReader) NextMetricPublication() (MetricPublicationKey, error) {
	if err := r.tx.Check(false); err != nil {
		return MetricPublicationKey{}, err
	}
	var next MetricPublicationKey
	found := false
	for key := range r.s.metricSamples {
		if !found || compareMetricPublicationKeys(key, next) < 0 {
			next = key
			found = true
		}
	}
	if !found {
		return MetricPublicationKey{}, ErrNotFound
	}
	return next, nil
}
func compareMetricPublicationKeys(a, b MetricPublicationKey) int {
	if order := a.Minute.Compare(b.Minute); order != 0 {
		return order
	}
	if order := strings.Compare(a.Topic.Partition, b.Topic.Partition); order != 0 {
		return order
	}
	if order := strings.Compare(a.Topic.AccountID, b.Topic.AccountID); order != 0 {
		return order
	}
	if order := strings.Compare(a.Topic.Region, b.Topic.Region); order != 0 {
		return order
	}
	return strings.Compare(a.Topic.Name, b.Topic.Name)
}
func (r memoryReader) MetricSamples(key MetricPublicationKey) ([]MetricSample, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	group := r.s.metricSamples[key]
	out := make([]MetricSample, 0, len(group))
	for sample, count := range group {
		out = append(out, MetricSample{Name: sample.name, Value: sample.value, SampleCount: count})
	}
	slices.SortFunc(out, func(a, b MetricSample) int {
		if order := strings.Compare(a.Name, b.Name); order != 0 {
			return order
		}
		return cmp.Compare(a.Value, b.Value)
	})
	return out, nil
}
func (r memoryReader) SigningKey() (SigningKeyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return SigningKeyRecord{}, err
	}
	if r.s.signingKey == nil {
		return SigningKeyRecord{}, ErrNotFound
	}
	return cloneSigningKey(*r.s.signingKey), nil
}
func (w memoryWriter) PutTopic(v TopicRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.topics[v.Key] = cloneTopic(v)
	return nil
}
func (w memoryWriter) DeleteTopic(k TopicKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key := range w.s.deduplication {
		if key.TopicID == w.s.topics[k].ID {
			delete(w.s.deduplication, key)
		}
	}
	if topic, exists := w.s.topics[k]; exists {
		w.deleteArchiveEntries(topic.ID)
	}
	delete(w.s.topics, k)
	return nil
}
func (w memoryWriter) PutSubscription(v SubscriptionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.subscriptions[v.Key] = cloneSubscription(v)
	return nil
}
func (w memoryWriter) OrphanTopicSubscriptions(topicID string, due time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k, v := range w.s.subscriptions {
		if v.TopicID == topicID {
			v.DeletionDue = &due
			v.Version++
			w.s.subscriptions[k] = v
		}
	}
	return nil
}
func (w memoryWriter) DeleteSubscription(k SubscriptionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.subscriptions, k)
	for id, v := range w.s.deliveries {
		if v.Subscription == k {
			w.deleteDelivery(id, v)
		}
	}
	return nil
}

func (w memoryWriter) DeleteSubscriptionNotifications(k SubscriptionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for id, delivery := range w.s.deliveries {
		if delivery.Subscription == k && w.s.messages[delivery.Message].Type == "" {
			w.deleteDelivery(id, delivery)
		}
	}
	return nil
}
func (w memoryWriter) PutMessage(v MessageRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.messages[v.Key] = cloneMessage(v)
	return nil
}
func (w memoryWriter) PutDelivery(v DeliveryRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if existing, exists := w.s.deliveries[v.ID]; exists {
		v.Message = existing.Message
		v.Replayed = existing.Replayed
	} else {
		w.s.messageReferences[v.Message]++
		if v.FIFOGroup != "" && !v.DeadLetter {
			w.s.deliveryTails[deliveryGroupKey{v.Subscription, v.FIFOGroup}] = v.ID
		}
	}
	w.s.deliveries[v.ID] = v
	if v.DeadLetter {
		key := deliveryGroupKey{v.Subscription, v.FIFOGroup}
		if w.s.deliveryTails[key] == v.ID {
			delete(w.s.deliveryTails, key)
		}
	}
	return nil
}
func (w memoryWriter) DeleteDelivery(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if v, ok := w.s.deliveries[id]; ok {
		w.deleteDelivery(id, v)
	}
	return nil
}
func (w memoryWriter) deleteDelivery(id string, v DeliveryRecord) {
	delete(w.s.deliveries, id)
	key := deliveryGroupKey{v.Subscription, v.FIFOGroup}
	if w.s.deliveryTails[key] == id {
		delete(w.s.deliveryTails, key)
	}
	w.releaseMessage(v.Message)
}

func (w memoryWriter) releaseMessage(key MessageKey) {
	if w.s.messageReferences[key] == 1 {
		delete(w.s.messageReferences, key)
		delete(w.s.messages, key)
	} else {
		w.s.messageReferences[key]--
	}
}
func (w memoryWriter) AddMetricSamples(key MetricPublicationKey, samples []MetricSample) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if len(samples) == 0 {
		return nil
	}
	group := w.s.metricSamples[key]
	if group == nil {
		group = make(map[metricSampleKey]int64, len(samples))
		w.s.metricSamples[key] = group
	}
	for _, sample := range samples {
		group[metricSampleKey{name: sample.Name, value: sample.Value}] += sample.SampleCount
	}
	return nil
}
func (w memoryWriter) DeleteMetricPublication(key MetricPublicationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.metricSamples, key)
	return nil
}
func (w memoryWriter) PutSigningKey(v SigningKeyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	v = cloneSigningKey(v)
	w.s.signingKey = &v
	return nil
}

func (r memoryReader) Deduplication(key DeduplicationKey) (DeduplicationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return DeduplicationRecord{}, err
	}
	v, ok := r.s.deduplication[key]
	if !ok {
		return DeduplicationRecord{}, ErrNotFound
	}
	return v, nil
}

func (r memoryReader) DeliveryTail(sub SubscriptionKey, group string) (string, error) {
	if err := r.tx.Check(false); err != nil {
		return "", err
	}
	return r.s.deliveryTails[deliveryGroupKey{sub, group}], nil
}

func (w memoryWriter) PutDeduplication(v DeduplicationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.deduplication[v.Key] = v
	return nil
}

func (w memoryWriter) DeleteExpiredDeduplication(topicID string, now time.Time) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for key, v := range w.s.deduplication {
		if key.TopicID == topicID && !v.Expires.After(now) {
			delete(w.s.deduplication, key)
		}
	}
	return nil
}

func (w memoryWriter) NextTopicSequence(key TopicKey) (uint64, error) {
	if err := w.tx.Check(true); err != nil {
		return 0, err
	}
	topic, exists := w.s.topics[key]
	if !exists {
		return 0, ErrNotFound
	}
	topic.Sequence++
	w.s.topics[key] = topic
	return topic.Sequence, nil
}

func cloneTopic(v TopicRecord) TopicRecord {
	v.Tags = maps.Clone(v.Tags)
	v.Policy.PrincipalIDs = maps.Clone(v.Policy.PrincipalIDs)
	v.Feedback = maps.Clone(v.Feedback)
	v.Archive = clonePointer(v.Archive)
	return v
}
func cloneSubscription(v SubscriptionRecord) SubscriptionRecord {
	v.DeletionDue = clonePointer(v.DeletionDue)
	return v
}
func cloneMessage(v MessageRecord) MessageRecord {
	v.EncryptedBody = slices.Clone(v.EncryptedBody)
	v.WrappedDataKey = slices.Clone(v.WrappedDataKey)
	v.EncryptionContext = maps.Clone(v.EncryptionContext)
	v.Publisher = awsctx.Clone(v.Publisher)
	v.Subject = clonePointer(v.Subject)
	v.Attributes = maps.Clone(v.Attributes)
	for name, a := range v.Attributes {
		a.DataType = clonePointer(a.DataType)
		a.StringValue = clonePointer(a.StringValue)
		a.BinaryValue = slices.Clone(a.BinaryValue)
		v.Attributes[name] = a
	}
	return v
}
func cloneSigningKey(v SigningKeyRecord) SigningKeyRecord {
	v.PrivateKeyDER = slices.Clone(v.PrivateKeyDER)
	v.CertificatePEM = slices.Clone(v.CertificatePEM)
	return v
}
func clonePointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
