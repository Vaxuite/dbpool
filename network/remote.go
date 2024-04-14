package network

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/Vaxuite/dbpool/protocol"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"net"
	"sync"
)

const (
	/* SSL Modes */
	SSL_MODE_REQUIRE     string = "require"
	SSL_MODE_VERIFY_CA   string = "verify-ca"
	SSL_MODE_VERIFY_FULL string = "verify-full"
	SSL_MODE_DISABLE     string = "disable"
)

var (
	log = logrus.New()
)

type ConnectionConfig struct {
	Host        string
	Port        string
	Username    string
	Database    string
	Password    string
	MinPoolSize int
	MaxPoolSize int
	SSLMode     string
}

type Remote struct {
	ID           uuid.UUID
	Config       ConnectionConfig
	conn         net.Conn
	lock         sync.RWMutex
	currentConns *semaphore.Weighted
	readd        func(r *Remote)
}

func NewRemote(config ConnectionConfig, currentConns *semaphore.Weighted, readd func(r *Remote)) *Remote {
	return &Remote{
		ID:           uuid.New(),
		currentConns: currentConns,
		readd:        readd,
		Config:       config,
	}
}

func (r *Remote) RemoteAddr() net.Addr {
	return r.conn.RemoteAddr()
}

func (r *Remote) Connect() error {
	r.lock.Lock()
	defer r.lock.Unlock()
	conn, err := r.dial(r.Config.Host + ":" + r.Config.Port)
	if err != nil {
		return fmt.Errorf("failed to connect to remote: %w", err)
	}
	r.conn = conn
	message := protocol.CreateStartupMessage(r.Config.Username, r.Config.Database, map[string]string{})
	if _, err = r.Send(message); err != nil {
		return fmt.Errorf("failed to send startup message: %w", err)
	}

	if ok, err := r.HandleAuthenticationRequest(); err != nil || !ok {
		if err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}
		if !ok {
			return fmt.Errorf("failed to authenticate")
		}
	}
	return nil
}

func (r *Remote) handleAuthClearText() (bool, error) {
	password := r.Config.Password
	passwordMessage := protocol.CreatePasswordMessage(password)

	_, err := r.conn.Write(passwordMessage)
	if err != nil {
		return false, err
	}

	response := make([]byte, 4096)
	_, err = r.conn.Read(response)
	if err != nil {
		return false, err
	}

	return protocol.IsAuthenticationOk(response), nil
}

func (r *Remote) Shutdown() {
	r.currentConns.Release(1)
	if err := r.conn.Close(); err != nil {
		log.WithError(err).Warnf("failed to close remote connection %s", r.RemoteAddr())
	}
}

func (r *Remote) HandleAuthenticationRequest() (bool, error) {
	message, _, err := r.Receive()
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
		return r.handleAuthClearText()
	case protocol.AuthenticationOk:
		/* Covers the case where the authentication type is 'cert' or 'trust' */
		return true, nil
	default:
		log.Errorf("Unknown authentication method: %d", authType)
	}

	return false, nil
}

func (r *Remote) Release() {
	r.readd(r)
}

func (r *Remote) Send(message []byte) (int, error) {
	return r.conn.Write(message)
}

func (r *Remote) Receive() ([]byte, int, error) {
	buffer := make([]byte, 4096)
	length, err := r.conn.Read(buffer)
	return buffer, length, err
}

func (r *Remote) dial(host string) (net.Conn, error) {
	connection, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}

	//todo: improve this
	if r.Config.SSLMode == "require" {
		message := protocol.NewMessageBuffer([]byte{})
		message.WriteInt32(8)
		message.WriteInt32(protocol.SSLRequestCode)

		/* Send the SSL request message. */
		_, err := connection.Write(message.Bytes())
		/* Receive SSL response message. */
		response := make([]byte, 4096)
		_, err = connection.Read(response)
		if err != nil {
			return nil, err
		}

		if len(response) > 0 && response[0] != 'S' {
			log.Error("The backend does not allow SSL connections.")
			connection.Close()
			return nil, fmt.Errorf("backend does not support ssl")
		} else {
			log.Debug("Attempting to upgrade connection.")
			connection = r.upgradeClientConnection(connection)
			log.Debug("Connection successfully upgraded.")
		}
	}
	return connection, nil
}

func (r *Remote) upgradeClientConnection(connection net.Conn) net.Conn {
	tlsConfig := tls.Config{}

	switch r.Config.SSLMode {
	case SSL_MODE_REQUIRE:
		tlsConfig.InsecureSkipVerify = true
	case SSL_MODE_DISABLE:
		return connection
	default:
		log.Fatalf("Unsupported sslmode %s\n", r.Config.SSLMode)
	}

	/* Upgrade the connection. */
	log.Info("Upgrading to SSL connection.")
	client := tls.Client(connection, &tlsConfig)

	return client
}
