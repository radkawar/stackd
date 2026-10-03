package kinesis

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"stackd/internal/awsctx"
)

const dataKeyReuse = 5 * time.Minute
const maxCachedDataKeys = 1024

type encryptionSlot struct {
	stream, incarnation, key string
	requester                [32]byte
	wrapped                  [32]byte
	decrypt                  bool
}

type encryptionMaterial struct {
	plain   [32]byte
	wrapped []byte
	arn     string
	expires time.Time
}

// Callers own value copies of plaintext; cache pruning/shutdown cannot race a
// cipher operation. The cache never holds its lock over KMS or repository work.
type encryptionCache struct {
	mu       sync.Mutex
	entries  map[encryptionSlot]*encryptionMaterial
	lifetime context.Context
	cancel   context.CancelFunc
	closed   bool
}

func newEncryptionCache() *encryptionCache {
	ctx, cancel := context.WithCancel(context.Background())
	return &encryptionCache{entries: make(map[encryptionSlot]*encryptionMaterial), lifetime: ctx, cancel: cancel}
}

func (c *encryptionCache) close() {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for slot, key := range c.entries {
		clear(key.plain[:])
		delete(c.entries, slot)
	}
}

func (c *encryptionCache) operation(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.lifetime, cancel)
	if c.lifetime.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func (c *encryptionCache) prune(now time.Time) {
	for slot, key := range c.entries {
		if !now.Before(key.expires) {
			clear(key.plain[:])
			delete(c.entries, slot)
		}
	}
}

func (c *encryptionCache) get(ctx context.Context, slot encryptionSlot, now time.Time) (encryptionMaterial, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	if c.closed || ctx.Err() != nil {
		return encryptionMaterial{}, false
	}
	if key := c.entries[slot]; key != nil {
		return *key, true
	}
	return encryptionMaterial{}, false
}

func (c *encryptionCache) put(ctx context.Context, slot encryptionSlot, key encryptionMaterial, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer clear(key.plain[:])
	c.prune(now)
	if c.closed || ctx.Err() != nil {
		return
	}
	if old := c.entries[slot]; old != nil {
		clear(old.plain[:])
		delete(c.entries, slot)
	}
	if len(c.entries) >= maxCachedDataKeys {
		var oldest encryptionSlot
		var expires time.Time
		for candidate, material := range c.entries {
			if expires.IsZero() || material.expires.Before(expires) {
				oldest, expires = candidate, material.expires
			}
		}
		clear(c.entries[oldest].plain[:])
		delete(c.entries, oldest)
	}
	stored := key
	c.entries[slot] = &stored
}

func (c *encryptionCache) drop(slot encryptionSlot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key := c.entries[slot]; key != nil {
		clear(key.plain[:])
		delete(c.entries, slot)
	}
}

func (c *encryptionCache) dropRequester(stream StreamRecord, requester [32]byte) {
	arn := stream.Key.ARN()
	c.mu.Lock()
	defer c.mu.Unlock()
	for slot, key := range c.entries {
		if slot.stream == arn && slot.incarnation == stream.EngineID && slot.requester == requester {
			clear(key.plain[:])
			delete(c.entries, slot)
		}
	}
}

func encryptionRequester(ctx context.Context) [32]byte {
	m := awsctx.FromContext(ctx)
	// Unlike SQS's measured role requester reuse, the Kinesis cost contract
	// explicitly distinguishes each assume-role credential. Include session
	// restrictions as well, without retaining credential metadata in the cache.
	encoded, _ := json.Marshal(struct {
		Partition, Account, AccessKey, Principal, PrincipalARN, Issuer, Session string
		Restricted                                                              bool
		Policies, PolicyARNs                                                    []string
		Tags                                                                    map[string]string
		SourceIdentity                                                          string
		Service                                                                 awsctx.ServicePrincipal
	}{m.Partition, m.AccountID, m.AccessKeyID, m.PrincipalID, m.PrincipalARN, m.IssuerID, m.SessionType, m.HasSessionPolicy, m.SessionPolicies, m.SessionPolicyARNs, m.SessionTags, m.SourceIdentity, m.ServicePrincipal})
	return sha256.Sum256(encoded)
}
