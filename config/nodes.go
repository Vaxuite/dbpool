package config

import "dbpool/pool"

func GetNodes() map[string]pool.ConnectionConfig {
	return map[string]pool.ConnectionConfig{
		"jack": pool.ConnectionConfig{
			Host:     "localhost:5432",
			Username: "vaxuite",
			Database: "jack",
			Password: "new_password",
		},
	}
}
