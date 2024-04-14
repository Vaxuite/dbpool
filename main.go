package main

import (
	config2 "github.com/Vaxuite/dbpool/config"
	"github.com/Vaxuite/dbpool/network"
	"github.com/Vaxuite/dbpool/pool"
	"github.com/Vaxuite/dbpool/proxy"
	"github.com/Vaxuite/dbpool/server"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func main() {
	config := config2.NewConfig()
	config.AddConfig(network.ConnectionConfig{
		Host:        "localhost:5432",
		Username:    "vaxuite",
		Database:    "jack",
		Password:    "pass",
		MinPoolSize: 5,
	})

	monitor := pool.NewMonitor()
	monitor.SetupPools(config)

	proxy := proxy.NewProxy(monitor, config)

	server := server.NewServer(server.Config{
		Port: 9090,
	}, proxy)

	if err := server.Start(); err != nil {
		panic(err)
	}
}
