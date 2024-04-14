package main

import (
	config2 "github.com/Vaxuite/dbpool/config"
	"github.com/Vaxuite/dbpool/pool"
	"github.com/Vaxuite/dbpool/proxy"
	"github.com/Vaxuite/dbpool/server"
	"github.com/sirupsen/logrus"
	"github.com/thought-machine/go-flags"
	"os"
)

var (
	opts struct {
		Config string `short:"c" long:"config"`
		Server struct {
			Host string `long:"host" default:"0.0.0.0"`
			Port int    `short:"p" long:"port" required:"true" default:"5430"`
		}
	}
)

var parser = flags.NewParser(&opts, flags.Default)

var log = logrus.New()

func main() {
	if _, err := parser.Parse(); err != nil {
		switch flagsErr := err.(type) {
		case flags.ErrorType:
			if flagsErr == flags.ErrHelp {
				os.Exit(0)
			}
			os.Exit(1)
		default:
			os.Exit(1)
		}
	}

	config := config2.NewConfig()
	if err := config.ReadFromFile(opts.Config); err != nil {
		log.WithError(err).Panic("failed to read config")
	}

	monitor := pool.NewMonitor()
	monitor.SetupPools(config)

	proxy := proxy.NewProxy(monitor, config)

	server := server.NewServer(server.Config{
		Host: opts.Server.Host,
		Port: opts.Server.Port,
	}, proxy)

	if err := server.Start(); err != nil {
		panic(err)
	}
}
