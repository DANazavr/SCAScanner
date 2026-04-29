# Configuration Guide

SCAScanner uses a JSON-based configuration system for managing Redis, cache, API, and scanning settings.

## Configuration File Locations

SCAScanner searches for configuration files in this priority order:

1. **Environment Variable** `SCASCANNER_CONFIG`: Explicit path to config file
   ```bash
   export SCASCANNER_CONFIG="/path/to/config.json"
   ```

2. **Current Directory**: `scascanner.json`
   ```bash
   ./scascanner.exe  # Looks for ./scascanner.json
   ```

3. **User Home**: `~/.scascanner/config.json`
   ```bash
   ~/.scascanner/config.json  # Linux/macOS
   C:\Users\{User}\.scascanner\config.json  # Windows
   ```

4. **System-wide** (Linux only): `/etc/scascanner/config.json`

## Creating Configuration

### Option 1: Save Default Config

Generate default configuration file:
```bash
./scascanner --save-config
```

This creates `~/.scascanner/config.json` with all default values.

### Option 2: Manual Creation

Copy `config.example.json` from the project:
```bash
cp config.example.json ~/.scascanner/config.json
```

### Option 3: Use Config File Directly

Specify config file path:
```bash
./scascanner -p /project/path --config /path/to/config.json
```

## Configuration Structure

```json
{
  "redis": {
    "address": "localhost:6379",    // Redis server address
    "password": "",                 // Redis password (empty if none)
    "db": 0,                        // Redis database number
    "enabled": true                 // Enable Redis caching
  },
  "cache": {
    "ttl": "24h",                   // Cache time-to-live
    "enable_local": true,           // Enable in-memory cache
    "enable_redis": true,           // Enable Redis cache
    "max_local_size": 10000         // Max items in local cache
  },
  "api": {
    "nvd_rate_limit": "200ms",      // NVD API rate limit
    "osv_rate_limit": "100ms",      // OSV API rate limit
    "timeout": "30s"                // API request timeout
  },
  "scan": {
    "max_workers": 1,               // Parallel scan workers
    "log_level": "info"             // Log level: debug, info, warn, error
  }
}
```

## Configuration Examples

### Example 1: Local Development (No Redis)

```json
{
  "redis": {
    "address": "localhost:6379",
    "enabled": false
  },
  "cache": {
    "enable_local": true,
    "enable_redis": false,
    "ttl": "24h"
  },
  "scan": {
    "log_level": "debug"
  }
}
```

### Example 2: Production with Redis

```json
{
  "redis": {
    "address": "redis-prod.example.com:6379",
    "password": "your-secure-password",
    "enabled": true
  },
  "cache": {
    "enable_local": true,
    "enable_redis": true,
    "ttl": "7d"
  },
  "api": {
    "timeout": "60s"
  },
  "scan": {
    "log_level": "info"
  }
}
```

### Example 3: Docker Redis with Custom Settings

```json
{
  "redis": {
    "address": "redis:6379",
    "password": "",
    "db": 1,
    "enabled": true
  },
  "cache": {
    "ttl": "72h",
    "enable_local": true,
    "enable_redis": true,
    "max_local_size": 50000
  },
  "scan": {
    "max_workers": 4
  }
}
```

## Command-Line Overrides

Command-line flags override configuration file settings:

```bash
# Override Redis address
./scascanner -p /project --redis-addr "redis-server:6379"

# Use specific config file
./scascanner -p /project --config ./custom-config.json

# Save configuration to default location
./scascanner --save-config
```

## Duration Format

Duration values use Go's time format:
- `s` - seconds (e.g., "30s")
- `m` - minutes (e.g., "5m")
- `h` - hours (e.g., "24h")
- `d` - days (e.g., "7d" = "168h")

Examples:
```json
{
  "cache": {
    "ttl": "24h"        // 24 hours
  },
  "api": {
    "timeout": "30s"    // 30 seconds
  }
}
```

## Environment-based Configuration

### Docker with Environment Variables

Set config via Docker environment variable:

```bash
docker run \
  -e SCASCANNER_CONFIG="/etc/scascanner/config.json" \
  -v /path/config.json:/etc/scascanner/config.json \
  scascanner:latest
```

### Kubernetes ConfigMap

Mount config file from ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: scascanner-config
data:
  config.json: |
    {
      "redis": {
        "address": "redis-service:6379"
      }
    }
---
apiVersion: v1
kind: Pod
metadata:
  name: scascanner
spec:
  containers:
  - name: scanner
    image: scascanner:latest
    env:
    - name: SCASCANNER_CONFIG
      value: /etc/config/config.json
    volumeMounts:
    - name: config
      mountPath: /etc/config
  volumes:
  - name: config
    configMap:
      name: scascanner-config
```

## Redis Configuration Details

### Remote Redis

```json
{
  "redis": {
    "address": "redis.example.com:6379",
    "password": "your-password",
    "enabled": true
  }
}
```

### Redis with SSL/TLS

For Redis servers with SSL, ensure proper certificate setup and use custom address format if your Redis client supports it.

### Redis Cluster

If using Redis Cluster, provide one node address (cluster discovery will handle the rest):

```json
{
  "redis": {
    "address": "redis-cluster-node-1:6379"
  }
}
```

## Logging Configuration

### Log Levels

- `debug` - Verbose output including cache hits/misses
- `info` - Standard informational messages (default)
- `warn` - Warning messages only
- `error` - Error messages only

### Example Debug Config

```json
{
  "scan": {
    "log_level": "debug"
  }
}
```

## Performance Tuning

### For Small Projects (< 50 dependencies)

```json
{
  "cache": {
    "ttl": "7d",
    "enable_local": true,
    "enable_redis": false
  },
  "api": {
    "timeout": "15s"
  }
}
```

### For Large Projects (> 500 dependencies)

```json
{
  "redis": {
    "address": "redis-server:6379",
    "enabled": true
  },
  "cache": {
    "ttl": "14d",
    "enable_local": true,
    "enable_redis": true,
    "max_local_size": 100000
  },
  "api": {
    "nvd_rate_limit": "300ms",
    "timeout": "60s"
  },
  "scan": {
    "max_workers": 4
  }
}
```

## Configuration Validation

Check if configuration is loaded correctly:

```bash
./scascanner -p /project --log-level debug 2>&1 | grep -i "config\|redis"
```

## Troubleshooting

### Config Not Found
If using `~/.scascanner/config.json`, ensure:
1. Directory exists: `mkdir -p ~/.scascanner`
2. File is readable: `chmod 644 ~/.scascanner/config.json`

### Invalid Configuration
If JSON is invalid:
- SCAScanner logs: "Warning: Failed to parse config file..."
- Falls back to defaults
- Check JSON syntax: Use a JSON validator

### Redis Not Connecting
Check in config:
- `"enabled": true` under redis section
- Address format is correct
- Redis service is running

## Best Practices

1. **Version Control**: Keep config files in git (minus sensitive passwords)
2. **Environment-Specific**: Use different configs for dev/prod
3. **Backup**: Keep backup of working configurations
4. **Audit**: Log configuration changes
5. **Secrets**: Use environment variables for Redis password
   ```bash
   export REDIS_PASSWORD="secret"
   # Then update config to use it
   ```

## Examples Directory

See `config.example.json` for default configuration template.
