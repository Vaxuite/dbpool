package pool

import "sync"

type DatabaseConfig struct {
}

type Database struct {
	lock        sync.Mutex
	connections []*Connection
}

func NewDatabase(config ConnectionConfig) *Database {
	d := &Database{}
	c := NewConnection(config)
	if err := c.Connect(); err != nil {
		panic(err)
	}
	d.connections = append(d.connections, c)
	return d
}
func (d *Database) GetConn() *Connection {
	d.lock.Lock()
	defer d.lock.Unlock()
	for _, c := range d.connections {
		if c.Inuse {
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
