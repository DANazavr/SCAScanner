# CVE Caching Documentation

## Overview

SCAScanner now includes a two-level caching system for CVE vulnerabilities to improve performance on repeated scans:

1. **Level 1 - Local In-Memory Cache**: Fast, per-process cache for immediate lookups
2. **Level 2 - Redis Cache**: Persistent cache shared across multiple scans and sessions (optional)

## How It Works

### Local Cache (Level 1)
- Stored in memory during the scanning process
- Thread-safe with RWMutex
- Immediately available with no network latency
- Lost when the process terminates

### Redis Cache (Level 2)
- Persistent distributed cache for cross-scan caching
- Default TTL: 24 hours
- Survives process termination
- Shared across multiple tool instances

## Configuration

### Redis Address

Configure Redis connection using:

1. **Environment Variable** (recommended):
```bash
export REDIS_ADDR="localhost:6379"
./scascanner -p /path/to/project
```

2. **Command Line Flag**:
```bash
./scascanner -p /path/to/project --redis-addr "localhost:6379"
```

3. **Default**:
```
localhost:6379
```

### Redis Connection

If Redis is unavailable:
- Tool logs a warning: "Redis connection failed... (falling back to local cache only)"
- Continues with local cache only
- No tool failure - graceful degradation

## Cache Keys

Cache entries use this format:
```
cve:{packageName}:{packageVersion}
```

Example:
```
cve:lodash:4.17.21
cve:express:^4.17.1
cve:axios:>=0.21.1
```

## Performance Impact

### First Scan (No Cache)
- Full API requests to NVD and OSV
- Time: ~2-5 minutes (depends on dependencies count)

### Repeated Scan (With Cache)
- Same machine, same process:
  - Cache hits from Level 1 (local memory)
  - Time: ~2-5 minutes (API calls still needed for uncached packages)
  
- Different process with Redis:
  - Cache hits from Level 2 (Redis)
  - Time: Significantly reduced

### Example with 100 dependencies

**First scan**: 3 minutes (0% cache hits)
**Second scan** (same process): 3 minutes (depends on duplicate packages)
**Third scan** (different process with Redis): 1 minute (high cache hit rate)

## Cache Logging

The tool logs cache operations:

```
LocalCache SET: cve:express:^4.17.1 (1137 vulns)
LocalCache HIT: cve:express:^4.17.1
Redis SET: cve:lodash:~4.17.20 (13 vulns) with TTL 24h0m0s
Redis HIT: cve:axios:>=0.21.1
```

## Redis Setup

### Quick Start (Docker)

```bash
docker run -d -p 6379:6379 redis:latest
```

### Docker Compose

Create `docker-compose.yml`:
```yaml
version: '3'
services:
  redis:
    image: redis:latest
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

Then run:
```bash
docker-compose up -d
```

### Local Redis Installation

**Windows**: Use Windows Subsystem for Linux or Redis for Windows
**Linux**: `apt-get install redis-server`
**macOS**: `brew install redis`

## Cache Invalidation

The cache automatically expires after 24 hours. To force cache invalidation:

1. **Clear local cache**: Restart the tool (new process)
2. **Clear Redis cache**: 
   ```bash
   redis-cli FLUSHDB
   ```

## Best Practices

1. **Use Redis for production**: Enables cross-process caching
2. **Monitor Redis**: Use `redis-cli` to check cache size:
   ```bash
   redis-cli INFO stats
   redis-cli DBSIZE
   ```
3. **Regular scans**: Set up periodic scans to keep cache fresh
4. **Update CVE data**: Manually clear cache when you want fresh data from APIs

## Troubleshooting

### Redis Connection Warning
```
Warning: Redis connection failed at localhost:6379: dial tcp...
```
**Solution**: Check if Redis is running (`redis-cli ping` should return PONG)

### Cache Not Working
1. Check logs for cache operations
2. Verify Redis is accessible: `redis-cli ping`
3. Ensure REDIS_ADDR environment variable is correct
4. Check file permissions if using Redis persistence

### Cache Memory Issues
If Redis uses too much memory:
```bash
# Set max memory policy
redis-cli CONFIG SET maxmemory-policy allkeys-lru
redis-cli CONFIG SET maxmemory 500mb
```

## Implementation Details

### Cache Interface
```go
type Cache interface {
    Get(ctx context.Context, key string) ([]models.Vulnerability, error)
    Set(ctx context.Context, key string, value []models.Vulnerability) error
    Close() error
}
```

### Files Modified
- `pkg/cache/cache.go` - Cache implementation
- `internal/scanner/cve.go` - SearchCVE with caching
- `internal/scanner/scanner.go` - VulnScanner with cache field
- `cmd/scascanner/main.go` - Cache initialization
- `go.mod` - Redis dependency

## Future Improvements

- [ ] Configurable TTL per dependency
- [ ] Cache statistics reporting
- [ ] Cache warm-up on startup
- [ ] Selective cache invalidation by date
- [ ] S3/alternative storage backends for cache
