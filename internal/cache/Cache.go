package cache

import (
	"github.com/blazskufca/dns_server_in_go/internal/Message"
	"log/slog"
	"math"
	"sync"
	"time"
)

type cachedResponse struct {
	message   *Message.Message
	expiresAt time.Time
}

// DNSCache represents a simple cache for DNS records
type DNSCache struct {
	mu     sync.RWMutex
	cache  map[string]cachedResponse
	logger *slog.Logger
}

// NewDNSCache creates a new DNS cache
func NewDNSCache(logger *slog.Logger) *DNSCache {
	cache := &DNSCache{
		cache:  make(map[string]cachedResponse),
		logger: logger,
	}

	// Start cache cleanup goroutine
	go cache.periodicallyCleanup()

	return cache
}

// periodicallyCleanup removes expired cache entries every minute
func (c *DNSCache) periodicallyCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

// cleanup removes expired cache entries
func (c *DNSCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if entry.expiresAt.Before(now) {
			delete(c.cache, key)
			c.logger.Debug("Removed expired cache entry", slog.String("key", key))
		}
	}
}

// Get retrieves a cached DNS message if available and not expired
func (c *DNSCache) Get(key string) *Message.Message {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.cache[key]
	if !found {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.message
}

// Put adds a DNS message to the cache with TTL from the record
func (c *DNSCache) Put(key string, msg *Message.Message) {
	if msg == nil || len(msg.Answers) == 0 || msg.Header.GetQDCOUNT() == 0 {
		return
	}

	// Find the minimum TTL from all answer records
	minTTL := uint32(math.MaxUint32)
	for _, answer := range msg.Answers {
		if answer.GetTTL() < minTTL {
			minTTL = answer.GetTTL()
		}
	}

	// Don't cache if TTL is 0
	if minTTL == 0 {
		return
	}

	// Use minimum of actual TTL or 1 hour to prevent excessively long cache times
	cacheTTL := time.Duration(minTTL) * time.Second
	maxCacheTTL := 1 * time.Hour
	if cacheTTL > maxCacheTTL {
		cacheTTL = maxCacheTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[key] = cachedResponse{
		message:   msg,
		expiresAt: time.Now().Add(cacheTTL),
	}

	c.logger.Debug("Added DNS response to cache",
		slog.String("key", key),
		slog.Duration("ttl", cacheTTL))
}
