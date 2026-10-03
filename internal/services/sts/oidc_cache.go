package sts

import (
	"context"
	"slices"
	"sync"
	"time"
)

type oidcCacheEntry struct {
	keys OIDCKeySet
	used time.Time
}
type oidcKeyLoad struct {
	ready chan struct{}
	keys  OIDCKeySet
	err   error
}
type oidcKeyCache struct {
	mu      sync.Mutex
	entries map[string]oidcCacheEntry
	loading map[string]*oidcKeyLoad
}

func (c *oidcKeyCache) resolve(ctx context.Context, source OIDCProviderSource, provider OIDCProviderSnapshot, now time.Time, force bool) (OIDCKeySet, bool, error) {
	if err := ctx.Err(); err != nil {
		return OIDCKeySet{}, false, err
	}
	cacheKey := provider.ARN + "\x00" + provider.ID + "\x00" + provider.Version
	c.mu.Lock()
	if !force {
		if entry, exists := c.entries[cacheKey]; exists && now.Before(entry.keys.CacheUntil) {
			entry.used = now
			c.entries[cacheKey] = entry
			c.mu.Unlock()
			return cloneOIDCKeySet(entry.keys), true, nil
		}
	}
	if pending, exists := c.loading[cacheKey]; exists {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return OIDCKeySet{}, false, ctx.Err()
		case <-pending.ready:
			return cloneOIDCKeySet(pending.keys), false, pending.err
		}
	}
	if c.loading == nil {
		c.loading = map[string]*oidcKeyLoad{}
	}
	pending := &oidcKeyLoad{ready: make(chan struct{})}
	c.loading[cacheKey] = pending
	c.mu.Unlock()
	keys, err := source.ResolveOIDCSigningKeys(ctx, provider.ARN)
	if err == nil && (keys.ProviderID != provider.ID || keys.ProviderVersion != provider.Version || keys.IssuerURL != provider.IssuerURL) {
		err = invalidOIDCToken("The OIDC provider changed during discovery.")
	}
	if err == nil {
		err = ctx.Err()
	}
	c.mu.Lock()
	delete(c.loading, cacheKey)
	if err == nil && now.Before(keys.CacheUntil) {
		if c.entries == nil {
			c.entries = map[string]oidcCacheEntry{}
		}
		const capacity = 256
		if len(c.entries) >= capacity {
			var oldest string
			var last time.Time
			for key, entry := range c.entries {
				if oldest == "" || entry.used.Before(last) {
					oldest = key
					last = entry.used
				}
			}
			delete(c.entries, oldest)
		}
		c.entries[cacheKey] = oidcCacheEntry{keys: cloneOIDCKeySet(keys), used: now}
	}
	pending.keys = cloneOIDCKeySet(keys)
	pending.err = err
	close(pending.ready)
	c.mu.Unlock()
	return cloneOIDCKeySet(keys), false, err
}
func cloneOIDCKeySet(keys OIDCKeySet) OIDCKeySet {
	keys.SigningAlgorithms = slices.Clone(keys.SigningAlgorithms)
	keys.Keys = slices.Clone(keys.Keys)
	for i := range keys.Keys {
		key := &keys.Keys[i]
		key.Operations = slices.Clone(key.Operations)
		key.Certificates = slices.Clone(key.Certificates)
		for j := range key.Certificates {
			key.Certificates[j] = slices.Clone(key.Certificates[j])
		}
	}
	return keys
}
