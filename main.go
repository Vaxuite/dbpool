package main

import (
	"github.com/Vaxuite/dbpool/config"
	"github.com/Vaxuite/dbpool/pool"
	"github.com/Vaxuite/dbpool/proxy"
	"github.com/Vaxuite/dbpool/server"
)

func main() {
	pools := map[string]*pool.Database{}
	for _, node := range config.GetNodes() {
		pools[node.Database] = pool.NewDatabase(node)
	}

	proxy := proxy.NewProxy(pools["jack"])

	server := server.NewServer(server.Config{
		Port: 9090,
	}, proxy)

	if err := server.Start(); err != nil {
		panic(err)
	}
}
