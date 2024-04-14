package config

import (
	"github.com/Vaxuite/dbpool/network"
)

type Config struct {
	connectionConfig map[string]network.ConnectionConfig
}

func NewConfig() *Config {
	return &Config{connectionConfig: map[string]network.ConnectionConfig{}}
}

func (c *Config) AddConfig(config network.ConnectionConfig) {
	c.connectionConfig[config.Database] = config
}

func (c *Config) ConnectionConfig(dbName string) (network.ConnectionConfig, bool) {
	config, ok := c.connectionConfig[dbName]
	return config, ok
}

func (c *Config) ConnectionConfigs() map[string]network.ConnectionConfig {
	return c.connectionConfig
}
