package network

import (
	"github.com/Vaxuite/dbpool/protocol"
	"io"
	"net"
)

type Client struct {
	conn               net.Conn
	TransactionBackend *Remote
}

func NewClient(conn net.Conn) *Client {
	return &Client{
		conn: conn,
	}
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) Send(message []byte) (int, error) {
	return c.conn.Write(message)
}

func (c *Client) Receive() ([]byte, int, error) {
	buffer := make([]byte, 4096)
	length, err := c.conn.Read(buffer)
	return buffer, length, err
}

func (c *Client) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Client) SendReadyForQuery() {
	m1 := protocol.NewMessageBuffer([]byte{})
	m1.WriteByte(protocol.ReadyForQueryMessageType)
	m1.WriteInt32(5)
	m1.WriteByte(protocol.EmptyQueryMessageType)
	c.Send(m1.Bytes())
}

func (c *Client) SendError(pgError protocol.Error) {
	c.Send(pgError.GetMessage())
	c.SendReadyForQuery()
}

// AuthenticateClient - Establish and authenticate client connection to the backend.
//
//	This function simply handles the passing of messages from the client to the
//	backend necessary for startup/authentication of a connection. All
//	communication is between the client and the master node. If the client
//	authenticates successfully with the master node, then 'true' is returned and
//	the authenticating connection is terminated.
func (c *Client) AuthenticateClient(targetPassword string) (bool, error) {
	outgoing := protocol.NewMessageBuffer([]byte{})
	outgoing.WriteByte(protocol.AuthenticationMessageType)
	outgoing.WriteInt32(8)
	outgoing.WriteInt32(protocol.AuthenticationClearText)
	c.Send(outgoing.Bytes())

	response, _, err := c.Receive()
	if err != nil {
		// psql will close the connection in this case
		if err == io.EOF {
			return false, nil
		}
		return false, err
	}

	buf := protocol.NewMessageBuffer(response)
	buf.ReadByte()
	buf.ReadInt32()
	password, err := buf.ReadString()
	if err != nil {
		return false, err
	}
	if password != targetPassword {
		return false, nil
	}

	m := protocol.NewMessageBuffer([]byte{})
	m.WriteByte(protocol.AuthenticationMessageType)
	m.WriteInt32(8)
	m.WriteInt32(protocol.AuthenticationOk)
	c.Send(m.Bytes())

	c.SendReadyForQuery()

	return false, nil
}

func (c *Client) Validate(message []byte) (string, string) {
	var clientUser string
	var clientDatabase string

	startup := protocol.NewMessageBuffer(message)

	startup.Seek(8) // Seek past the message length and protocol version.

	for {
		param, err := startup.ReadString()

		if err == io.EOF || param == "\x00" {
			break
		}

		switch param {
		case "user":
			clientUser, err = startup.ReadString()
		case "database":
			clientDatabase, err = startup.ReadString()
		}
	}
	return clientDatabase, clientUser
}
