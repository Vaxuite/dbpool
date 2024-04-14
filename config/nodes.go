package config

import (
	"fmt"
	"github.com/Vaxuite/dbpool/network"
	"github.com/please-build/gcfg"
	"github.com/sirupsen/logrus"
	"strconv"
	"strings"
)

var log = logrus.New()

type Config struct {
	connectionConfig map[string]network.ConnectionConfig
}

func NewConfig() *Config {
	return &Config{connectionConfig: map[string]network.ConnectionConfig{}}
}

func (c *Config) ReadFromFile(path string) error {
	config, err := LoadConfig(path)
	if err != nil {
		return err
	}
	for _, db := range config.Database {
		c.connectionConfig[db.Name] = network.ConnectionConfig{
			Host:        db.Host,
			Port:        strconv.Itoa(db.Port),
			Username:    db.User,
			Database:    db.Name,
			Password:    db.Password,
			MinPoolSize: db.MinConnections,
			MaxPoolSize: db.MaxConnections,
			SSLMode:     db.SSLMode,
		}
	}
	return nil
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

// LoadConfig loads the given config file.
func LoadConfig(filename string) (*Configuration, error) {
	cfg := &Configuration{}
	cfg.Server.AppName = "deadpool"

	if err := gcfg.ReadFileInto(cfg, filename); err != nil {
		if gcfg.FatalOnly(err) != nil {
			return nil, err
		}
		log.Warningf("Error in config file: %s", err)
	}

	if len(cfg.Database) == 0 {
		return nil, fmt.Errorf("no databases specified in config")
	}

	// Validate some parts of the config
	for name, db := range cfg.Database {
		switch db.SSLMode {
		case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
			// All known
		case "":
			db.SSLMode = "prefer"
		default:
			return nil, fmt.Errorf("unknown SSL mode for database %s: %s (should be one of: disable, allow, prefer, require, verify-ca, verify-full)", name, db.SSLMode)
		}
		switch db.DBAuthMechanism {
		case "password", "client_certificates", "none":
		case "":
			db.DBAuthMechanism = "password" // This is the default in dbv2 and it should be the default here as well.
		default:
			return nil, fmt.Errorf("unknown DBAuthMechanism for database %s: %s (should be one of: password, client_certificates, none, aws_iam)", name, db.DBAuthMechanism)
		}
		for _, replica := range db.Replica {
			if replica == name {
				return nil, fmt.Errorf("database %s specifies itself as a read replica", name)
			} else if _, present := cfg.Database[replica]; !present {
				return nil, fmt.Errorf("database %s specifies unknown database %s as a read replica", name, replica)
			}
		}
		if db.MaxConnections == 0 {
			db.MaxConnections = 10
			if db.MaxConnections < db.MinConnections {
				db.MaxConnections = db.MinConnections
			}
		} else if db.MaxConnections < db.MinConnections {
			return nil, fmt.Errorf("database %s misconfigured; max %d is less than min %d", name, db.MaxConnections, db.MinConnections)
		} else if db.MaxConnections < 0 {
			return nil, fmt.Errorf("database %s misconfigured; negative max connections: %d", name, db.MaxConnections)
		} else if db.MinConnections < 0 {
			return nil, fmt.Errorf("database %s misconfigured; negative min connections: %d", name, db.MinConnections)
		}
		if db.Name == "" {
			db.Name = name
		}
		if len(strings.TrimSpace(db.Host)) == 0 {
			return nil, fmt.Errorf("database %s misconfigured; host can not be empty", name)
		}
	}
	//for name, user := range cfg.User {
	//	if user.Database == "" {
	//		return nil, fmt.Errorf("user %s does not have a database specified", name)
	//	} else if _, present := cfg.Database[user.Database]; !present {
	//		return nil, fmt.Errorf("user %s specifies database %s which doesn't exist", name, user.Database)
	//	}
	//}
	return cfg, nil
}

// Configuration is the database configuration for Deadpool.
type Configuration struct {
	Server struct {
		AppName string
	}

	Database map[string]*Database

	User map[string]*User
}

// A User represents a user in our configuration, which maps to a Database.
type User struct {
	Password string
	Database string
}

// A Database represents a database in our configuration & the details to connect to it.
type Database struct {
	Host            string
	Port            int
	User            string
	Password        string
	Name            string
	MinConnections  int
	MaxConnections  int
	SSLMode         string
	Replica         []string
	DBAuthMechanism string
}
