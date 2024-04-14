package pool

import (
	"bytes"
	"dbpool/protocol"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

type ConnectionConfig struct {
	Host     string
	Username string
	Database string
	Password string
}

type Connection struct {
	Config ConnectionConfig
	conn   net.Conn
	lock   sync.RWMutex
	Inuse  bool
}

func NewConnection(config ConnectionConfig) *Connection {
	return &Connection{
		Config: config,
	}
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Connection) Connect() error {
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

	//c.Receive()

	//if c.Config.Password != "" {
	c.HandleAuthenticationRequest()
	//}

	//if err := c.ReadUntil(protocol.ReadyForQueryMessageType); err != nil {
	//	return err
	//}
	return nil
}

func (c *Connection) handleAuthClearText() bool {
	password := c.Config.Password
	passwordMessage := protocol.CreatePasswordMessage(password)

	_, err := c.conn.Write(passwordMessage)

	if err != nil {
		log.Error("Error sending clear text password message to the backend.")
		log.Errorf("Error: %s", err.Error())
	}

	response := make([]byte, 4096)
	_, err = c.conn.Read(response)

	if err != nil {
		log.Error("Error receiving clear text authentication response.")
		log.Errorf("Error: %s", err.Error())
	}

	return protocol.IsAuthenticationOk(response)
}

func (c *Connection) Shutdown() {

}

func (c *Connection) HandleAuthenticationRequest() bool {
	message, _, err := c.Receive()
	if err != nil {
		return false
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
	case protocol.AuthenticationKerberosV5:
		log.Error("KerberosV5 authentication is not currently supported.")
	case protocol.AuthenticationClearText:
		log.Info("Authenticating with clear text password.")
		return c.handleAuthClearText()
	case protocol.AuthenticationMD5:
		log.Error("MD5 authentication is not currently supported.")
	case protocol.AuthenticationSCM:
		log.Error("SCM authentication is not currently supported.")
	case protocol.AuthenticationGSS:
		log.Error("GSS authentication is not currently supported.")
	case protocol.AuthenticationGSSContinue:
		log.Error("GSS authentication is not currently supported.")
	case protocol.AuthenticationSSPI:
		log.Error("SSPI authentication is not currently supported.")
	case protocol.AuthenticationOk:
		/* Covers the case where the authentication type is 'cert' or 'trust' */
		return true
	default:
		log.Errorf("Unknown authentication method: %d", authType)
	}

	return false
}

func (c *Connection) Acquire() bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.Inuse {
		return false
	}
	c.Inuse = true
	return true
}

func (c *Connection) Release() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Inuse = false
}
