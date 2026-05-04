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

type Cache interface {
	Get(ctx context.Context, key string) ([]models.Vulnerability, error)
	Set(ctx context.Context, key string, value []models.Vulnerability) error
	Close() error
}

type LocalCache struct {
	mu    sync.RWMutex
	store map[string][]models.Vulnerability
}

func NewLocalCache() *LocalCache {
	return &LocalCache{
		store: make(map[string][]models.Vulnerability),
	}
}

func (lc *LocalCache) Get(_ context.Context, key string) ([]models.Vulnerability, error) {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	if vuln, exists := lc.store[key]; exists {
		log.Printf("LocalCache HIT: %s", key)
		return vuln, nil
	}

	return nil, fmt.Errorf("key not found")
}

func (lc *LocalCache) Set(_ context.Context, key string, value []models.Vulnerability) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.store[key] = value
	log.Printf("LocalCache SET: %s (%d vulns)", key, len(value))
	return nil
}

func (lc *LocalCache) Close() error {
	return nil
}

type RedisCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewRedisCache(addr string, password string, db int, ttl time.Duration) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

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

func (rc *RedisCache) Close() error {
	if rc == nil || rc.client == nil {
		return nil
	}
	return rc.client.Close()
}

type MultiLevelCache struct {
	redis *RedisCache
	local *LocalCache
}

func NewMultiLevelCache(redisAddr string, redisPassword string, redisDB int, ttl time.Duration) *MultiLevelCache {
	local := NewLocalCache()

	redis := NewRedisCache(redisAddr, redisPassword, redisDB, ttl)

	return &MultiLevelCache{
		redis: redis,
		local: local,
	}
}

func (mlc *MultiLevelCache) Get(ctx context.Context, key string) ([]models.Vulnerability, error) {
	if mlc.redis != nil {
		if vulns, err := mlc.redis.Get(ctx, key); err == nil {
			_ = mlc.local.Set(ctx, key, vulns)
			return vulns, nil
		}
	}

	return mlc.local.Get(ctx, key)
}

func (mlc *MultiLevelCache) Set(ctx context.Context, key string, value []models.Vulnerability) error {
	if err := mlc.local.Set(ctx, key, value); err != nil {
		log.Printf("LocalCache SET failed: %v", err)
	}

	if mlc.redis != nil {
		if err := mlc.redis.Set(ctx, key, value); err != nil {
			log.Printf("Redis SET failed (continuing with local cache): %v", err)
		}
	}

	return nil
}

func (mlc *MultiLevelCache) Close() error {
	if mlc.redis != nil {
		_ = mlc.redis.Close()
	}
	return mlc.local.Close()
}
