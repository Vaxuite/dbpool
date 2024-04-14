package pool

import (
	"context"
	"fmt"
	"github.com/Vaxuite/dbpool/network"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"sync"
)

type Database struct {
	lock             sync.Mutex
	connections      chan *network.Remote
	connectionConfig network.ConnectionConfig
	currentConns     *semaphore.Weighted
}

func NewDatabase(connectionConfig network.ConnectionConfig) (*Database, error) {
	d := &Database{
		connectionConfig: connectionConfig,
		currentConns:     semaphore.NewWeighted(int64(connectionConfig.MaxPoolSize)),
		connections:      make(chan *network.Remote, 10000),
	}

	return d, nil
}

func (d *Database) monitorConnections() {
	for {
		if err := d.makeConnection(); err != nil {
			log.WithError(err).Error("failed to make connection")
		}
	}
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
	go d.monitorConnections()
	return nil
}

func (d *Database) makeConnection() error {
	d.currentConns.Acquire(context.Background(), 1)
	fmt.Println("making")
	c := network.NewRemote(d.connectionConfig, d.currentConns, func(r *network.Remote) {
		d.connections <- r
	})
	if err := c.Connect(); err != nil {
		return err
	}
	//todo: proper context

	d.connections <- c
	return nil
}

func (d *Database) GetConn() *network.Remote {
	return <-d.connections
}
