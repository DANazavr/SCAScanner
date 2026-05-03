package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Config holds all application configuration
type Config struct {
	Redis RedisConfig `json:"redis"`
	Cache CacheConfig `json:"cache"`
	API   APIConfig   `json:"api"`
	Scan  ScanConfig  `json:"scan"`
}

// RedisConfig holds Redis-specific settings
type RedisConfig struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
	DB       int    `json:"db"`
	Enabled  bool   `json:"enabled"`
}

// CacheConfig holds cache-specific settings
type CacheConfig struct {
	TTL          string `json:"ttl"`            // Duration string like "24h", "7d"
	EnableLocal  bool   `json:"enable_local"`   // Enable in-memory cache
	EnableRedis  bool   `json:"enable_redis"`   // Enable Redis cache
	MaxLocalSize int    `json:"max_local_size"` // Max items in local cache
}

// APIConfig holds API-specific settings
type APIConfig struct {
	NVDAPIKey    string `json:"nvd_api_key"`    // NVD API key (optional, for higher rate limits)
	NVDRateLimit string `json:"nvd_rate_limit"` // Duration like "200ms"
	OSVRateLimit string `json:"osv_rate_limit"` // Duration like "100ms"
	Timeout      string `json:"timeout"`        // API timeout like "30s"
}

// ScanConfig holds scanning-specific settings
type ScanConfig struct {
	MaxWorkers int    `json:"max_workers"`
	LogLevel   string `json:"log_level"` // "debug", "info", "warn", "error"
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Redis: RedisConfig{
			Address:  "redis-14410.crce218.eu-central-1-1.ec2.cloud.redislabs.com:14410",
			Username: "default",
			Password: "0WhdZnMeY5mBiWY5QVpY1lpcrgmFxO3F",
			DB:       0,
			Enabled:  true,
		},
		Cache: CacheConfig{
			TTL:          "24h",
			EnableLocal:  true,
			EnableRedis:  true,
			MaxLocalSize: 10000,
		},
		Scan: ScanConfig{
			MaxWorkers: 1,
			LogLevel:   "info",
		},
	}
}

// GetConfigPath returns the config file path
// Priority:
// 1. SCASCANNER_CONFIG env variable
// 2. ./scascanner.json (current directory)
// 3. ~/.scascanner/config.json (user home)
// 4. /etc/scascanner/config.json (system-wide, Linux only)
func GetConfigPath() string {
	// Check environment variable first
	if envPath := os.Getenv("SCASCANNER_CONFIG"); envPath != "" {
		return envPath
	}

	// Check current directory
	if _, err := os.Stat("./config/config.json"); err == nil {
		return "./config/config.json"
	}

	// Check user home directory
	if home, err := os.UserHomeDir(); err == nil {
		userConfigPath := filepath.Join(home, ".scascanner", "config.json")
		if _, err := os.Stat(userConfigPath); err == nil {
			return userConfigPath
		}
	}

	// System-wide config (Linux)
	if _, err := os.Stat("/etc/scascanner/config.json"); err == nil {
		return "/etc/scascanner/config.json"
	}

	// Return default path (will be created if needed)
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".scascanner", "config.json")
}

// Load loads configuration from file or uses defaults
func Load() *Config {
	config := DefaultConfig()
	configPath := GetConfigPath()

	// Try to read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config file not found at %s, using defaults", configPath)
			return config
		}
		log.Printf("Warning: Failed to read config file: %v, using defaults", err)
		return config
	}

	// Parse JSON
	if err := json.Unmarshal(data, config); err != nil {
		log.Printf("Warning: Failed to parse config file: %v, using defaults", err)
		return config
	}

	log.Printf("Loaded config from: %s", configPath)
	return config
}

// LoadFromFile loads configuration from a specific file
func LoadFromFile(filePath string) (*Config, error) {
	config := DefaultConfig()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// Save saves configuration to file
func (c *Config) Save(filePath string) error {
	// Create directory if not exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	log.Printf("Configuration saved to: %s", filePath)
	return nil
}

// SaveDefault saves default configuration to the default location
func SaveDefault() error {
	config := DefaultConfig()
	return config.Save(GetConfigPath())
}

// Override applies command-line overrides to the config
type Override struct {
	RedisAddr   string
	RedisPwd    string
	LogLevel    string
	CacheTTL    string
	EnableRedis *bool
	EnableLocal *bool
}

// ApplyOverride applies command-line overrides to configuration
func (c *Config) ApplyOverride(override Override) {
	if override.RedisAddr != "" {
		c.Redis.Address = override.RedisAddr
	}
	if override.RedisPwd != "" {
		c.Redis.Password = override.RedisPwd
	}
	if override.LogLevel != "" {
		c.Scan.LogLevel = override.LogLevel
	}
	if override.CacheTTL != "" {
		c.Cache.TTL = override.CacheTTL
	}
	if override.EnableRedis != nil {
		c.Redis.Enabled = *override.EnableRedis
		c.Cache.EnableRedis = *override.EnableRedis
	}
	if override.EnableLocal != nil {
		c.Cache.EnableLocal = *override.EnableLocal
	}
}

// String returns a formatted string representation of the config
func (c *Config) String() string {
	data, _ := json.MarshalIndent(c, "", "  ")
	return string(data)
}
