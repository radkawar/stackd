package eventbridge

import (
	"crypto/sha256"
	"sync"
	"time"
)

// Native captures establish warm reuse and later cold failures, not an exact
// fleet-wide TTL. Thirty service seconds is the local bounded reuse policy.
const busDataKeyReuse = 30 * time.Second
const busCachedKeyLimit = 1024

type busKeyMaterial struct {
	plain            [32]byte
	wrapped          []byte
	arn              string
	configuration    [32]byte
	created, expires time.Time
}
type busKeyCache struct {
	mu      sync.Mutex
	entries map[BusKey]*busKeyMaterial
	closed  bool
}

func (c *busKeyCache) prune(now time.Time) {
	for key, material := range c.entries {
		if !now.Before(material.expires) {
			clear(material.plain[:])
			delete(c.entries, key)
		}
	}
}
func (c *busKeyCache) get(bus BusRecord, now time.Time) (busKeyMaterial, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	if c.closed {
		return busKeyMaterial{}, false
	}
	material := c.entries[bus.Key]
	if material == nil {
		return busKeyMaterial{}, false
	}
	if material.created != bus.Created || material.configuration != sha256.Sum256(bus.ConfigurationDataKey) {
		clear(material.plain[:])
		delete(c.entries, bus.Key)
		return busKeyMaterial{}, false
	}
	return *material, true
}
func (c *busKeyCache) put(bus BusRecord, plain, wrapped []byte, arn string, now time.Time) {
	if len(plain) != 32 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	if c.closed {
		return
	}
	if c.entries == nil {
		c.entries = make(map[BusKey]*busKeyMaterial)
	}
	if previous := c.entries[bus.Key]; previous != nil {
		clear(previous.plain[:])
		delete(c.entries, bus.Key)
	}
	if len(c.entries) >= busCachedKeyLimit {
		var oldest BusKey
		var deadline time.Time
		for key, value := range c.entries {
			if deadline.IsZero() || value.expires.Before(deadline) {
				oldest, deadline = key, value.expires
			}
		}
		clear(c.entries[oldest].plain[:])
		delete(c.entries, oldest)
	}
	material := &busKeyMaterial{wrapped: wrapped, arn: arn, configuration: sha256.Sum256(bus.ConfigurationDataKey), created: bus.Created, expires: now.Add(busDataKeyReuse)}
	copy(material.plain[:], plain)
	c.entries[bus.Key] = material
}
func (c *busKeyCache) drop(key BusKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if material := c.entries[key]; material != nil {
		clear(material.plain[:])
		delete(c.entries, key)
	}
}
func (c *busKeyCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for key, material := range c.entries {
		clear(material.plain[:])
		delete(c.entries, key)
	}
}
