package pool

import (
	"github.com/sirupsen/logrus"
	"net"
)

var log = logrus.New()

func (c *Connection) Send(message []byte) (int, error) {
	return c.conn.Write(message)
}

func (c *Connection) Receive() ([]byte, int, error) {
	buffer := make([]byte, 4096)
	length, err := c.conn.Read(buffer)
	return buffer, length, err
}

func (c *Connection) dial(host string) (net.Conn, error) {
	connection, err := net.Dial("tcp", host)

	if err != nil {
		return nil, err
	}

	return connection, nil
}
