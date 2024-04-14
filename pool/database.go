package pool

import (
	"github.com/Vaxuite/dbpool/network"
	"golang.org/x/sync/errgroup"
	"sync"
)

type Database struct {
	lock             sync.Mutex
	connections      []*network.Remote
	connectionConfig network.ConnectionConfig
}

func NewDatabase(connectionConfig network.ConnectionConfig) (*Database, error) {
	d := &Database{connectionConfig: connectionConfig}
	if err := d.setupPool(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Database) setupPool() error {
	wg := errgroup.Group{}

	for x := 0; x < d.connectionConfig.MinPoolSize; x++ {
		wg.Go(func() error {
			return d.makeConnection()
		})
	}
	if err := wg.Wait(); err != nil {
		return err
	}
	return nil
}

func (d *Database) makeConnection() error {
	c := network.NewRemote(d.connectionConfig)
	if err := c.Connect(); err != nil {
		return err
	}
	d.lock.Lock()
	d.connections = append(d.connections, c)
	d.lock.Unlock()
	return nil
}

func (d *Database) GetConn() *network.Remote {
	d.lock.Lock()
	defer d.lock.Unlock()
	for _, c := range d.connections {
		if c.InUse {
			continue
		}
		ok := c.Acquire()
		if !ok {
			continue
		}
		return c
	}
	return nil
}
