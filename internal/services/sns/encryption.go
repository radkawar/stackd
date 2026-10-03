package sns

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// DataKeys authorizes and audits envelope encryption through the KMS provider.
type DataKeys interface {
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
}

type dataKeySlot struct{ topicID, identifier, requester string }
type cachedDataKey struct {
	plaintext, wrapped []byte
	arn                string
	context            map[string]string
	expires            time.Time
}

const dataKeyReusePeriod = 5 * time.Minute

// Native retained HTTP delivery remained warm beyond publication's five-minute
// window, then required KMS again. Ten minutes is the local reuse policy, not a
// measured fleet-wide AWS cache deadline.
const retainedDataKeyReusePeriod = 10 * time.Minute

type bodyKey struct {
	slot dataKeySlot
	body string
}
type keyPreparation struct {
	slot  dataKeySlot
	topic TopicKey
	body  *string
}
type publicationKeys struct {
	s         *Service
	ctx       context.Context
	requester string
	keys      map[dataKeySlot]cachedDataKey
	bodies    map[bodyKey][]byte
	pending   *keyPreparation
}

var errPreparePublicationKey = errors.New("SNS publication encryption requires preparation")

func snsEncryptionContext(ctx context.Context, topic TopicKey) map[string]string {
	values := map[string]string{"aws:sns:topicArn": topic.ARN()}
	m := awsctx.FromContext(ctx)
	service, _, _ := strings.Cut(m.ServicePrincipal.Name, ".")
	switch service {
	case "events", "cloudwatch", "cloudtrail", "s3":
		values["aws:sns:sourceArn"] = m.ServicePrincipal.SourceARN
		values["aws:sns:sourceAccount"] = m.AccountID
	}
	return values
}

// Ordinary role sessions share by issuer and retained authority, not issuance/name.
// TODO: Comeback establish other session-field, federation and remaining service-source cache sharing boundaries.
// TODO: Comeback establish identifier/key-state propagation, HTTPS admission and other producers' KMS source context.
func publicationRequester(ctx context.Context) string {
	m := awsctx.FromContext(ctx)
	if m.SessionType == "AssumeRole" {
		m.PrincipalID, m.PrincipalARN, m.AccessKeyID = m.IssuerID, m.IssuerARN, ""
	}
	b, _ := json.Marshal(struct {
		Account, Principal, ARN, AccessKey, Service, Source string
		Restricted                                          bool
		Policies, PolicyARNs                                []string
		Tags                                                map[string]string
		SourceIdentity, Provider                            string
		MFA                                                 bool
		MFAAt                                               time.Time
		Context                                             map[string][]string
		Via                                                 []string
	}{
		Account: m.AccountID, Principal: m.PrincipalID, ARN: m.PrincipalARN,
		AccessKey: m.AccessKeyID, Service: m.ServicePrincipal.Name, Source: m.ServicePrincipal.SourceARN,
		Restricted: m.HasSessionPolicy, Policies: m.SessionPolicies, PolicyARNs: m.SessionPolicyARNs,
		Tags: m.SessionTags, SourceIdentity: m.SourceIdentity, Provider: m.FederatedProvider,
		MFA: m.MFAPresent, MFAAt: m.MFAAuthenticatedAt, Context: m.SessionContext, Via: m.CalledVia,
	})
	return string(b)
}

// A cache miss rolls back all SNS state/events before any KMS or AES operation.
// Retrying rechecks topic incarnation, configuration, authority and subscriptions.
// Each command attempt isolates rejection from a caller's enclosing mutation;
// the caller retains the API failure outcome only after these writes roll back.
func (s *Service) updatePublication(ctx context.Context, fn func(Transaction, *publicationKeys) error) error {
	work := &publicationKeys{s: s, ctx: ctx}
	defer func() {
		for _, key := range work.keys {
			clear(key.plaintext)
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		work.pending = nil
		err := s.repository.Attempt(ctx, func(tx Transaction) error { return fn(tx, work) })
		if !errors.Is(err, errPreparePublicationKey) {
			return err
		}
		if err := work.prepare(ctx); err != nil {
			return err
		}
	}
}

func (w *publicationKeys) require(topic TopicRecord) error {
	if topic.KmsMasterKeyID == "" {
		return nil
	}
	if w.keys == nil {
		w.requester = publicationRequester(w.ctx)
		w.keys = make(map[dataKeySlot]cachedDataKey)
		w.bodies = make(map[bodyKey][]byte)
	}
	slot := dataKeySlot{topic.ID, topic.KmsMasterKeyID, w.requester}
	if key, ok := w.keys[slot]; ok {
		if w.s.clock.Now().Before(key.expires) {
			return nil
		}
		clear(key.plaintext)
		delete(w.keys, slot)
		for body := range w.bodies {
			if body.slot == slot {
				delete(w.bodies, body)
			}
		}
	}
	w.pending = &keyPreparation{slot: slot, topic: topic.Key}
	return errPreparePublicationKey
}

func (w *publicationKeys) seal(topic TopicRecord, message *MessageRecord) error {
	message.Publisher = awsctx.FromContext(w.ctx)
	if topic.KmsMasterKeyID == "" {
		return nil
	}
	slot := dataKeySlot{topic.ID, topic.KmsMasterKeyID, w.requester}
	body := bodyKey{slot, message.Body}
	sealed, ok := w.bodies[body]
	if !ok {
		w.pending = &keyPreparation{slot: slot, topic: topic.Key, body: ptr(message.Body)}
		return errPreparePublicationKey
	}
	key := w.keys[slot]
	message.Body, message.EncryptedBody, message.WrappedDataKey, message.KMSKeyARN = "", sealed, key.wrapped, key.arn
	message.EncryptionContext = key.context
	return nil
}

func (w *publicationKeys) prepare(ctx context.Context) error {
	r := w.pending
	if r.body != nil {
		key := w.keys[r.slot]
		block, err := aes.NewCipher(key.plaintext)
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		w.bodies[bodyKey{r.slot, *r.body}] = aead.Seal(nonce, nonce, []byte(*r.body), []byte(r.topic.ARN()))
		return nil
	}
	s := w.s
	if s.keys == nil {
		return failure("KMSNotFound", "The KMS provider is unavailable.")
	}
	s.keyMu.Lock()
	for slot, key := range s.keyCache {
		if !s.clock.Now().Before(key.expires) {
			clear(key.plaintext)
			delete(s.keyCache, slot)
		}
	}
	key, ok := s.keyCache[r.slot]
	if ok {
		key.plaintext = slices.Clone(key.plaintext)
		key.wrapped = slices.Clone(key.wrapped)
	}
	s.keyMu.Unlock()
	if ok {
		w.keys[r.slot] = key
		return nil
	}
	id := r.slot.identifier
	if id == "alias/aws/sns" {
		var rejected *awswire.Error
		id, rejected = s.keys.EnsureServiceKey(ctx, "sns")
		if rejected != nil {
			return snsKeyError(rejected)
		}
	}
	keyContext := snsEncryptionContext(ctx, r.topic)
	generated, wrapped, _, rejected := s.keys.GenerateDataKey(ctx, id, keyContext)
	clear(generated)
	if rejected != nil {
		return snsKeyError(rejected)
	}
	plain, arn, rejected := s.keys.Decrypt(ctx, wrapped, keyContext)
	if rejected != nil {
		clear(plain)
		return snsKeyError(rejected)
	}
	key = cachedDataKey{plaintext: plain, wrapped: wrapped, arn: arn, context: keyContext, expires: s.clock.Now().Add(dataKeyReusePeriod)}
	w.keys[r.slot] = key
	key.plaintext = slices.Clone(plain)
	key.wrapped = slices.Clone(wrapped)
	s.keyMu.Lock()
	if old, exists := s.keyCache[r.slot]; exists {
		clear(old.plaintext)
	}
	s.keyCache[r.slot] = key
	retainedSlot := dataKeySlot{r.topic.ARN(), string(wrapped), ""}
	if old, exists := s.keyCache[retainedSlot]; exists {
		clear(old.plaintext)
	}
	key.plaintext = slices.Clone(plain)
	key.expires = s.clock.Now().Add(retainedDataKeyReusePeriod)
	s.keyCache[retainedSlot] = key
	s.keyMu.Unlock()
	return nil
}

func (s *Service) openMessage(ctx context.Context, message *MessageRecord, archive bool) *awswire.Error {
	if message.KMSKeyARN == "" {
		return nil
	}
	if s.keys == nil {
		return failure("KMSNotFound", "The KMS provider is unavailable.")
	}
	var plain []byte
	var rejected *awswire.Error
	s.keyMu.Lock()
	slot := dataKeySlot{message.Topic.ARN(), string(message.WrappedDataKey), ""}
	if key, ok := s.keyCache[slot]; ok {
		if s.clock.Now().Before(key.expires) {
			plain = slices.Clone(key.plaintext)
		} else {
			clear(key.plaintext)
			delete(s.keyCache, slot)
		}
	}
	s.keyMu.Unlock()
	if plain == nil {
		if !archive {
			publisher := message.Publisher
			publisher.RequestID = awsctx.FromContext(ctx).RequestID
			publisher.ParentEventID = message.ParentEventID
			ctx = awsctx.WithMetadata(ctx, publisher)
		}
		plain, _, rejected = s.keys.Decrypt(ctx, message.WrappedDataKey, message.EncryptionContext)
		if rejected == nil {
			s.keyMu.Lock()
			if old, exists := s.keyCache[slot]; exists {
				clear(old.plaintext)
			}
			s.keyCache[slot] = cachedDataKey{plaintext: slices.Clone(plain), expires: s.clock.Now().Add(retainedDataKeyReusePeriod)}
			s.keyMu.Unlock()
		}
	}
	defer clear(plain)
	if rejected != nil {
		return snsKeyError(rejected)
	}
	block, err := aes.NewCipher(plain)
	if err != nil {
		return failure("KMSInvalidState", "Invalid retained data key.")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return failure("KMSInvalidState", "Invalid retained data key.")
	}
	n := aead.NonceSize()
	if len(message.EncryptedBody) < n {
		return failure("KMSInvalidState", "Invalid retained encrypted message.")
	}
	body, err := aead.Open(nil, message.EncryptedBody[:n], message.EncryptedBody[n:], []byte(message.Topic.ARN()))
	if err != nil {
		return failure("KMSInvalidState", "Unable to decrypt retained message.")
	}
	message.Body = string(body)
	clear(body)
	return nil
}

func snsKeyError(err *awswire.Error) *awswire.Error {
	code := "KMSInvalidState"
	switch err.Code {
	case "AccessDeniedException":
		code = "KMSAccessDenied"
	case "NotFoundException":
		code = "KMSNotFound"
	case "DisabledException":
		code = "KMSDisabled"
	case "ThrottlingException":
		code = "KMSThrottling"
	case "OptInRequired":
		return failure("KMSOptInRequired", err.Message, 403)
	default:
		if err.StatusCode >= 500 {
			return failure("InternalError", err.Message, 500)
		}
	}
	return failure(code, err.Message, 400)
}
