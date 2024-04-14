package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/Vaxuite/dbpool/protocol"
	"github.com/sirupsen/logrus"
	"net"
	"sync"
)

var (
	log = logrus.New()
)

type ConnectionConfig struct {
	Host        string
	Username    string
	Database    string
	Password    string
	MinPoolSize int
	MaxPoolSize int
}

type Remote struct {
	Config ConnectionConfig
	conn   net.Conn
	lock   sync.RWMutex
	InUse  bool
}

func NewRemote(config ConnectionConfig) *Remote {
	return &Remote{
		Config: config,
	}
}

func (c *Remote) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Remote) Connect() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	conn, err := c.dial(c.Config.Host)
	if err != nil {
		return fmt.Errorf("failed to connect to remote: %w", err)
	}
	c.conn = conn
	message := protocol.CreateStartupMessage(c.Config.Username, c.Config.Database, map[string]string{})
	if _, err = c.Send(message); err != nil {
		return fmt.Errorf("failed to send startup message: %w", err)
	}

	if ok, err := c.HandleAuthenticationRequest(); err != nil || ok {
		if err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}
		if !ok {
			return fmt.Errorf("failed to authenticate")
		}
	}
	return nil
}

func (c *Remote) handleAuthClearText() (bool, error) {
	fmt.Println(c.Config.Password + c.Config.Username)
	password := c.Config.Password
	passwordMessage := protocol.CreatePasswordMessage(password)

	_, err := c.conn.Write(passwordMessage)
	if err != nil {
		return false, err
	}

	response := make([]byte, 4096)
	_, err = c.conn.Read(response)
	if err != nil {
		return false, err
	}

	return protocol.IsAuthenticationOk(response), nil
}

func (c *Remote) Shutdown() {
	if err := c.conn.Close(); err != nil {
		log.WithError(err).Warn("failed to close remote connection %s", c.RemoteAddr())
	}
}

func (c *Remote) HandleAuthenticationRequest() (bool, error) {
	message, _, err := c.Receive()
	if err != nil {
		return false, err
	}

	var msgLength int32
	var authType int32

	// Read message length.
	reader := bytes.NewReader(message[1:5])
	binary.Read(reader, binary.BigEndian, &msgLength)

	// Read authentication type.
	reader.Reset(message[5:9])
	binary.Read(reader, binary.BigEndian, &authType)

	switch authType {
	case protocol.AuthenticationClearText:
		log.Debug("Authenticating with clear text password.")
		return c.handleAuthClearText()
	case protocol.AuthenticationOk:
		/* Covers the case where the authentication type is 'cert' or 'trust' */
		return true, nil
	default:
		log.Errorf("Unknown authentication method: %d", authType)
	}

	return false, nil
}

func (c *Remote) Acquire() bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.InUse {
		return false
	}
	c.InUse = true
	return true
}

func (c *Remote) Release() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.InUse = false
}

func (c *Remote) Send(message []byte) (int, error) {
	return c.conn.Write(message)
}

func (c *Remote) Receive() ([]byte, int, error) {
	buffer := make([]byte, 4096)
	length, err := c.conn.Read(buffer)
	return buffer, length, err
}

func (c *Remote) dial(host string) (net.Conn, error) {
	connection, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	return connection, nil
}
