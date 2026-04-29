package cache

import (
	"SCAScanner/internal/models"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache interface defines methods for caching operations
type Cache interface {
	Get(ctx context.Context, key string) ([]models.Vulnerability, error)
	Set(ctx context.Context, key string, value []models.Vulnerability) error
	Close() error
}

// LocalCache implements in-memory caching
type LocalCache struct {
	mu    sync.RWMutex
	store map[string][]models.Vulnerability
}

// NewLocalCache creates a new in-memory cache
func NewLocalCache() *LocalCache {
	return &LocalCache{
		store: make(map[string][]models.Vulnerability),
	}
}

// Get retrieves vulnerabilities from local cache
func (lc *LocalCache) Get(_ context.Context, key string) ([]models.Vulnerability, error) {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	if vuln, exists := lc.store[key]; exists {
		log.Printf("LocalCache HIT: %s", key)
		return vuln, nil
	}

	return nil, fmt.Errorf("key not found")
}

// Set stores vulnerabilities in local cache
func (lc *LocalCache) Set(_ context.Context, key string, value []models.Vulnerability) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.store[key] = value
	log.Printf("LocalCache SET: %s (%d vulns)", key, len(value))
	return nil
}

// Close closes the local cache (no-op for local cache)
func (lc *LocalCache) Close() error {
	return nil
}

// RedisCache implements Redis-based caching
type RedisCache struct {
	client *redis.Client
	ttl    time.Duration
}

// NewRedisCache creates a new Redis cache
// If connection fails, returns nil and logs a warning
func NewRedisCache(addr string, password string, db int, ttl time.Duration) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Redis connection failed at %s: %v (falling back to local cache only)", addr, err)
		client.Close()
		return nil
	}

	log.Printf("Redis cache initialized successfully at %s with TTL: %v", addr, ttl)
	return &RedisCache{
		client: client,
		ttl:    ttl,
	}
}

// Get retrieves vulnerabilities from Redis cache
func (rc *RedisCache) Get(ctx context.Context, key string) ([]models.Vulnerability, error) {
	if rc == nil || rc.client == nil {
		return nil, fmt.Errorf("redis cache not available")
	}

	val, err := rc.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("key not found")
		}
		log.Printf("Redis GET error for key %s: %v", key, err)
		return nil, err
	}

	var vulns []models.Vulnerability
	if err := json.Unmarshal([]byte(val), &vulns); err != nil {
		log.Printf("Failed to unmarshal Redis value for key %s: %v", key, err)
		return nil, err
	}

	log.Printf("Redis HIT: %s", key)
	return vulns, nil
}

// Set stores vulnerabilities in Redis cache
func (rc *RedisCache) Set(ctx context.Context, key string, value []models.Vulnerability) error {
	if rc == nil || rc.client == nil {
		return fmt.Errorf("redis cache not available")
	}

	jsonVal, err := json.Marshal(value)
	if err != nil {
		log.Printf("Failed to marshal value for key %s: %v", key, err)
		return err
	}

	if err := rc.client.Set(ctx, key, jsonVal, rc.ttl).Err(); err != nil {
		log.Printf("Redis SET error for key %s: %v", key, err)
		return err
	}

	log.Printf("Redis SET: %s (%d vulns) with TTL %v", key, len(value), rc.ttl)
	return nil
}

// Close closes the Redis connection
func (rc *RedisCache) Close() error {
	if rc == nil || rc.client == nil {
		return nil
	}
	return rc.client.Close()
}

// MultiLevelCache combines Redis and local cache with fallback logic
type MultiLevelCache struct {
	redis *RedisCache
	local *LocalCache
}

// NewMultiLevelCache creates a two-level cache system
// Tries Redis first, falls back to local cache if Redis unavailable
func NewMultiLevelCache(redisAddr string, redisPassword string, redisDB int, ttl time.Duration) *MultiLevelCache {
	local := NewLocalCache()

	// Try to connect to Redis (will log warning if fails)
	redis := NewRedisCache(redisAddr, redisPassword, redisDB, ttl)

	return &MultiLevelCache{
		redis: redis,
		local: local,
	}
}

// Get retrieves vulnerabilities, trying Redis first then local cache
func (mlc *MultiLevelCache) Get(ctx context.Context, key string) ([]models.Vulnerability, error) {
	// Try Redis first
	if mlc.redis != nil {
		if vulns, err := mlc.redis.Get(ctx, key); err == nil {
			// Also cache in local for faster access
			_ = mlc.local.Set(ctx, key, vulns)
			return vulns, nil
		}
	}

	// Fall back to local cache
	return mlc.local.Get(ctx, key)
}

// Set stores vulnerabilities in both levels
func (mlc *MultiLevelCache) Set(ctx context.Context, key string, value []models.Vulnerability) error {
	// Store in local cache (always succeeds)
	if err := mlc.local.Set(ctx, key, value); err != nil {
		log.Printf("LocalCache SET failed: %v", err)
	}

	// Store in Redis (if available)
	if mlc.redis != nil {
		if err := mlc.redis.Set(ctx, key, value); err != nil {
			log.Printf("Redis SET failed (continuing with local cache): %v", err)
		}
	}

	return nil
}

// Close closes both cache levels
func (mlc *MultiLevelCache) Close() error {
	if mlc.redis != nil {
		_ = mlc.redis.Close()
	}
	return mlc.local.Close()
}
