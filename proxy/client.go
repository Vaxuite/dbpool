package proxy

import (
	"github.com/Vaxuite/dbpool/pool"
	"github.com/Vaxuite/dbpool/protocol"
	"io"
	"net"
)

type Client struct {
	conn               net.Conn
	TransactionBackend *pool.Connection
}

func NewClient(conn net.Conn) *Client {
	return &Client{
		conn: conn,
	}
}

func (c *Client) Close() {

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
func (c *Client) AuthenticateClient() (bool, error) {
	m := protocol.NewMessageBuffer([]byte{})
	m.WriteByte(protocol.AuthenticationMessageType)
	m.WriteInt32(8)
	m.WriteInt32(protocol.AuthenticationOk)
	c.Send(m.Bytes())

	c.SendReadyForQuery()

	///*
	// * While the response for the master node is not an AuthenticationOK or
	// * ErrorResponse keep relaying the mesages to/from the client/master.
	// */
	//messageType := protocol.GetMessageType(message)
	//
	//for !protocol.IsAuthenticationOk(message) &&
	//	(messageType != protocol.ErrorMessageType) {
	//	Send(client, message[:length])
	//	message, length, err = Receive(client)
	//
	//	/*
	//	 * Must check that the client has not closed the connection.  This in
	//	 * particular is specific to 'psql' when it prompts for a password.
	//	 * Apparently, when psql prompts the user for a password it closes the
	//	 * original connection, and then creates a new one. Eventually the
	//	 * following send/receives would timeout and no 'meaningful' messages
	//	 * are relayed. This would ultimately cause an infinite loop.  Thus it
	//	 * is better to short circuit here if the client connection has been
	//	 * closed.
	//	 */
	//	if (err != nil) && (err == io.EOF) {
	//		log.Info("The client closed the connection.")
	//		log.Debug("If the client is 'psql' and the authentication method " +
	//			"was 'password', then this behavior is expected.")
	//		return false, err
	//	}
	//
	//	Send(master, message[:length])
	//
	//	message, length, err = Receive(master)
	//
	//	messageType = protocol.GetMessageType(message)
	//}
	//
	///*
	// * If the last response from the master node was AuthenticationOK, then
	// * terminate the connection and return 'true' for a successful
	// * authentication of the client.
	// */
	//log.Debug("client auth: checking authentication repsonse")
	//if protocol.IsAuthenticationOk(message) {
	//	termMsg := protocol.GetTerminateMessage()
	//	Send(master, termMsg)
	//	Send(client, message[:length])
	//	return true, nil
	//}
	//
	//if protocol.GetMessageType(message) == protocol.ErrorMessageType {
	//	err = protocol.ParseError(message)
	//	log.Error("Error occurred on client startup.")
	//	log.Errorf("Error: %s", err.Error())
	//} else {
	//	log.Error("Unknown error occurred on client startup.")
	//}
	//
	//Send(client, message[:length])

	return false, nil
}

func ValidateClient(message []byte) bool {
	var clientUser string
	var clientDatabase string

	//creds := config.GetCredentials()

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

	return clientUser == "jack" && clientDatabase == "jack"
}
