package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type Config struct {
	Redis RedisConfig `json:"redis"`
	Cache CacheConfig `json:"cache"`
	Scan  ScanConfig  `json:"scan"`
}

type RedisConfig struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
	DB       int    `json:"db"`
	Enabled  bool   `json:"enabled"`
}

type CacheConfig struct {
	TTL          string `json:"ttl"`
	EnableLocal  bool   `json:"enable_local"`
	EnableRedis  bool   `json:"enable_redis"`
	MaxLocalSize int    `json:"max_local_size"`
}

type ScanConfig struct {
	MaxWorkers int    `json:"max_workers"`
	LogLevel   string `json:"log_level"`
}

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

func GetConfigPath() string {
	if envPath := os.Getenv("SCASCANNER_CONFIG"); envPath != "" {
		return envPath
	}

	if _, err := os.Stat("./config/config.json"); err == nil {
		return "./config/config.json"
	}

	if home, err := os.UserHomeDir(); err == nil {
		userConfigPath := filepath.Join(home, ".scascanner", "config.json")
		if _, err := os.Stat(userConfigPath); err == nil {
			return userConfigPath
		}
	}

	if _, err := os.Stat("/etc/scascanner/config.json"); err == nil {
		return "/etc/scascanner/config.json"
	}

	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".scascanner", "config.json")
}

func Load() *Config {
	config := DefaultConfig()
	configPath := GetConfigPath()

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config file not found at %s, using defaults", configPath)
			return config
		}
		log.Printf("Warning: Failed to read config file: %v, using defaults", err)
		return config
	}

	if err := json.Unmarshal(data, config); err != nil {
		log.Printf("Warning: Failed to parse config file: %v, using defaults", err)
		return config
	}

	log.Printf("Loaded config from: %s", configPath)
	return config
}

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

func (c *Config) Save(filePath string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	log.Printf("Configuration saved to: %s", filePath)
	return nil
}

func SaveDefault() error {
	config := DefaultConfig()
	return config.Save(GetConfigPath())
}

type Override struct {
	RedisAddr   string
	RedisPwd    string
	LogLevel    string
	CacheTTL    string
	EnableRedis *bool
	EnableLocal *bool
}

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

func (c *Config) String() string {
	data, _ := json.MarshalIndent(c, "", "  ")
	return string(data)
}
