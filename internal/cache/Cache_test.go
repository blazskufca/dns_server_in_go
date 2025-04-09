package cache

import (
	"fmt"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Class"
	"github.com/blazskufca/dns_server_in_go/internal/DNS_Type"
	"github.com/blazskufca/dns_server_in_go/internal/Message"
	"github.com/blazskufca/dns_server_in_go/internal/RR"
	"github.com/blazskufca/dns_server_in_go/internal/header"
	"github.com/blazskufca/dns_server_in_go/internal/question"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestDNSCache_Get(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cache := NewDNSCache(logger)

	msg := createMessageWithTTL(t, 300)

	result := cache.Get("test.example.com")
	if result != nil {
		t.Fatalf("Expected nil for cache miss, got %v", result)
	}

	cache.Put("test.example.com", msg)
	result = cache.Get("test.example.com")
	if result == nil {
		t.Errorf("Expected cache hit, got nil")
	}
}

func TestDNSCache_Expiration(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cache := NewDNSCache(logger)

	msg := createMessageWithTTL(t, 1)

	key := "short-ttl.example.com"
	cache.Put(key, msg)

	result := cache.Get(key)
	if result == nil {
		t.Fatalf("Expected cache hit before expiration, got nil")
	}

	time.Sleep(2 * time.Second)

	result = cache.Get(key)
	if result != nil {
		t.Fatalf("Expected nil for expired entry, got %v", result)
	}
}

func TestDNSCache_Put(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cache := NewDNSCache(logger)

	tests := []struct { //nolint:govet
		name     string
		key      string
		msg      *Message.Message
		maxCache time.Duration
		ttl      uint32
		wantHit  bool
	}{
		{
			name:    "Nil message",
			key:     "nil.example.com",
			msg:     nil,
			wantHit: false,
		},
		{
			name:    "Empty answers",
			key:     "empty.example.com",
			msg:     &Message.Message{Answers: []RR.RR{}},
			wantHit: false,
		},
		{
			name:    "Zero TTL",
			key:     "zero-ttl.example.com",
			msg:     createMessageWithTTL(t, 0),
			wantHit: false,
		},
		{
			name:     "Normal TTL",
			key:      "normal-ttl.example.com",
			msg:      createMessageWithTTL(t, 300),
			wantHit:  true,
			ttl:      300,
			maxCache: 300 * time.Second,
		},
		{
			name:     "High TTL (should be capped)",
			key:      "high-ttl.example.com",
			msg:      createMessageWithTTL(t, 10000),
			wantHit:  true,
			ttl:      10000,
			maxCache: 1 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.Put(tt.key, tt.msg)
			result := cache.Get(tt.key)

			if tt.wantHit && result == nil {
				t.Fatalf("Expected cache hit, got miss")
			} else if !tt.wantHit && result != nil {
				t.Fatalf("Expected cache miss, got hit")
			}

			if tt.wantHit {
				cache.mu.RLock()
				entry, found := cache.cache[tt.key]
				cache.mu.RUnlock()

				if !found {
					t.Fatalf("Entry not found in cache")
					return
				}

				expectedExpiration := time.Now().Add(tt.maxCache)
				if expectedExpiration.Sub(entry.expiresAt) > 1*time.Second ||
					entry.expiresAt.Sub(expectedExpiration) > 1*time.Second {
					t.Fatalf("Wrong expiration time. Expected around %v, got %v",
						expectedExpiration, entry.expiresAt)
				}
			}
		})
	}
}

func TestDNSCache_Cleanup(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cache := NewDNSCache(logger)

	msg1 := createMessageWithTTL(t, 1)
	key1 := "expired.example.com"
	cache.Put(key1, msg1)

	msg2 := createMessageWithTTL(t, 3600)
	key2 := "not-expired.example.com"
	cache.Put(key2, msg2)

	time.Sleep(2 * time.Second)

	cache.cleanup()

	if ce := cache.Get(key1); ce != nil {
		t.Fatalf("Expected cache miss, got %v", ce)
	}

	if ce := cache.Get(key2); ce == nil {
		t.Fatalf("Expected cache hit, got %v", ce)
	}
}

func TestDNSCache_ConcurrentAccess(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cache := NewDNSCache(logger)
	key := "concurrent.example.com"

	msg := createMessageWithTTL(t, 300)
	cache.Put("concurrent.example.com", msg)

	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(t *testing.T, key string, wnum int, wg *sync.WaitGroup) {
			t.Helper()
			defer wg.Done()

			for j := 0; j < iterations; j++ {
				if j%2 == 0 {
					if c := cache.Get(key); c == nil {
						t.Errorf("Cache miss, expected cache hit")
					}
				} else {
					key1 := fmt.Sprintf("%d-worker.%d-iteration.%s", wnum, j, key)
					cache.Put(key1, msg)
				}
			}
		}(t, key, i, &wg)
	}
	wg.Wait()
	for k := range cache.cache {
		t.Logf("Cache entry: %v", k)
	}
}

func TestDNSCache_MinimumTTL(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cache := NewDNSCache(logger)

	msg := createMessageWithTTL(t, 300)
	msg.Answers = append(msg.Answers, RR.RR{TTL: 600})
	msg.Answers = append(msg.Answers, RR.RR{TTL: 200}) // This should be the minimum
	msg.Answers = append(msg.Answers, RR.RR{TTL: 900})
	err := msg.Header.SetANCOUNT(len(msg.Answers))
	if err != nil {
		t.Fatal(err)
	}
	cache.Put("multi-ttl.example.com", msg)

	cache.mu.RLock()
	entry, found := cache.cache["multi-ttl.example.com"]
	cache.mu.RUnlock()

	if !found {
		t.Errorf("Entry not found in cache")
		return
	}

	expectedExpiration := time.Now().Add(200 * time.Second)
	if expectedExpiration.Sub(entry.expiresAt) > 1*time.Second ||
		entry.expiresAt.Sub(expectedExpiration) > 1*time.Second {
		t.Errorf("Wrong expiration time. Expected around %v, got %v",
			expectedExpiration, entry.expiresAt)
	}
}

func TestDNSCache_PeriodicallyCleanup(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cache := NewDNSCache(logger)

	// Override ticker for testing
	ticker := time.NewTicker(50 * time.Millisecond)
	go func() {
		for range ticker.C {
			cache.cleanup()
		}
	}()

	key := "periodic-cleanup.example.com"
	msg := createMessageWithTTL(t, 1)
	cache.Put(key, msg)

	time.Sleep(2 * time.Second)

	// Check if entry was removed
	if ce := cache.Get(key); ce != nil {
		t.Fatalf("Expected cache miss, got %v", ce)
	}

	ticker.Stop()
}

func createMessageWithTTL(t *testing.T, ttl uint32) *Message.Message {
	t.Helper()
	msg := &Message.Message{
		Header: header.Header{},
		Questions: []question.Question{
			{
				Name:  "example.com",
				Type:  DNS_Type.A,
				Class: DNS_Class.IN,
			},
		},
		Answers: []RR.RR{
			{TTL: ttl},
		},
	}

	err := msg.Header.SetQDCOUNT(1)
	if err != nil {
		t.Fatal(err)
	}

	return msg
}
