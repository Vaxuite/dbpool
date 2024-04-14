package main

import (
	"dbpool/config"
	pool2 "dbpool/pool"
	proxy2 "dbpool/proxy"
	"dbpool/server"
)

func main() {
	pools := map[string]*pool2.Database{}
	for _, node := range config.GetNodes() {
		pool := pool2.NewDatabase(node)
		pools[node.Database] = pool
	}

	proxy := proxy2.NewProxy(pools["jack"])

	server := server.NewServer(server.Config{
		Port: 9090,
	}, proxy)

	if err := server.Start(); err != nil {
		panic(err)
	}
}
