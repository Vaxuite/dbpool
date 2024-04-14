package pool

import (
	"github.com/Vaxuite/dbpool/network"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

type NodeConfig interface {
	ConnectionConfigs() map[string]network.ConnectionConfig
}

type Monitor struct {
	pools map[string]*Database
}

func NewMonitor() *Monitor {
	return &Monitor{pools: map[string]*Database{}}
}

func (m *Monitor) Pool(db string) *Database {
	//todo: should probably check this exists
	return m.pools[db]
}

func (m *Monitor) SetupPools(config NodeConfig) {
	for _, node := range config.ConnectionConfigs() {
		db, err := NewDatabase(node)
		if err != nil {
			log.WithError(err).Panicf("failed to initialise pool %s", node.Database)
			continue
		}
		if err := db.setupPool(); err != nil {
			log.WithError(err).Panicf("failed to initialise pool %s", node.Database)
			continue
		}
		m.pools[node.Database] = db
	}
}
