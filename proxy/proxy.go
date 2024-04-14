package proxy

import (
	"fmt"
	"github.com/Vaxuite/dbpool/network"
	"github.com/Vaxuite/dbpool/pool"
	"github.com/Vaxuite/dbpool/protocol"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"strings"
	"sync"
)

var (
	log = logrus.New()
)

type Monitor interface {
	Pool(database string) *pool.Database
}

type Config interface {
	ConnectionConfig(dbName string) (network.ConnectionConfig, bool)
}

type Proxy struct {
	monitor Monitor
	clients []net.Conn
	lock    *sync.Mutex
	config  Config
}

func NewProxy(monitor Monitor, config Config) *Proxy {
	p := &Proxy{
		config:  config,
		lock:    &sync.Mutex{},
		monitor: monitor,
	}

	return p
}

func (p *Proxy) ValidateAndAuthenticate(message []byte, length int, client *network.Client) (string, bool) {
	pgError := protocol.Error{
		Severity: protocol.ErrorSeverityFatal,
		Code:     protocol.ErrorCodeInvalidAuthorizationSpecification,
		Message:  "could not validate user/database",
	}

	dbName, user := client.Validate(message)

	dbConfig, ok := p.config.ConnectionConfig(dbName)
	if !ok {
		client.SendError(pgError)
		return "", false
	}
	if dbConfig.Username != user {
		client.SendError(pgError)
		return "", false
	}

	ok, err := client.AuthenticateClient(dbConfig.Password)
	if err != nil || !ok {
		client.SendError(protocol.Error{
			Severity: protocol.ErrorSeverityFatal,
			Code:     protocol.ErrorCodeInvalidAuthorizationSpecification,
			Message:  "password supplied was incorrect",
		})
		if err != nil {
			log.WithError(err).Warn("failed to complete password flow")
		}
		return "", false
	}
	return dbName, true
}

// HandleConnection handle an incoming connection to the proxy
func (p *Proxy) HandleConnection(client *network.Client) error {
	/* Get the client startup message. */
	message, length, err := client.Receive()
	if err != nil {
		return fmt.Errorf("failed to recieve message from client: %w", err)
	}

	dbName, ok := p.ValidateAndAuthenticate(message, length, client)
	if !ok {
		return fmt.Errorf("failed to authenticate")
	}

	/* Process the client messages for the life of the connection. */
	for {
		message, length, err := client.Receive()

		if err != nil {
			switch err {
			case io.EOF:
				log.Infof("Client: %s - closed the connection", client.RemoteAddr())
			default:
				log.Errorf("Error reading from client connection %s", client.RemoteAddr())
				log.Errorf("Error: %s", err.Error())
			}
			break
		}

		messageType := protocol.GetMessageType(message)

		/*
		 * If the message is a simple query, then it can have read/write
		 * annotations attached to it. Therefore, we need to process it and
		 * determine which backend we need to send it to.
		 */
		if messageType == protocol.TerminateMessageType {
			log.Infof("Client: %s - disconnected", client.RemoteAddr())
			return nil
		} else if messageType == protocol.QueryMessageType {

			// This means we are not in a transaction so we must wait until a begin and then acquire one
			if client.TransactionBackend == nil {
				if ok, err := p.isBegin(message); !ok {
					client.SendError(err)
					continue
				}
				pool := p.monitor.Pool(dbName)
				backend := pool.GetConn()
				client.TransactionBackend = backend
			}

			txEnded, closeConnections, err := p.handleStatement(client, message, length)
			if err != nil {
				client.SendError(*err)
				client.TransactionBackend.Shutdown()
				client.TransactionBackend = nil
			}
			if closeConnections {
				client.TransactionBackend.Shutdown()
				client.Close()
				client.TransactionBackend = nil
				break
			}
			if txEnded {
				client.TransactionBackend.Release()
				client.TransactionBackend = nil
			}
		}
	}
	return nil
}

func (p *Proxy) isBegin(message []byte) (bool, protocol.Error) {
	messageBuffer := protocol.NewMessageBuffer(message[1:])
	messageBuffer.ReadInt32()
	s, err := messageBuffer.ReadString()
	if err != nil {
		return false, protocol.Error{
			Severity: protocol.ErrorSeverityFatal,
			Code:     protocol.ErrorCodeUndefinedFunction,
			Message:  "must start with begin",
		}
	}
	s = strings.ToLower(s)
	if !strings.HasPrefix(s, "begin") {
		return false, protocol.Error{
			Severity: protocol.ErrorSeverityFatal,
			Code:     protocol.ErrorCodeUndefinedFunction,
			Message:  "must start with begin",
		}
	}
	return true, protocol.Error{}
}

type transactionStatus byte

const (
	txnStatusIdle                transactionStatus = 'I'
	txnStatusIdleInTransaction   transactionStatus = 'T'
	txnStatusInFailedTransaction transactionStatus = 'E'
)

func (s transactionStatus) String() string {
	switch s {
	case txnStatusIdle:
		return "idle"
	case txnStatusIdleInTransaction:
		return "idle in transaction"
	case txnStatusInFailedTransaction:
		return "in a failed transaction"
	default:
		return "unknown transactionStatus"
	}

	panic("not reached")
}

func (p *Proxy) handleStatement(client *network.Client, message []byte, length int) (bool, bool, *protocol.Error) {
	if _, err := client.TransactionBackend.Send(message[:length]); err != nil {
		return false, true, &protocol.Error{
			Severity: protocol.ErrorSeverityFatal,
			Code:     protocol.ErrorCodeConnectionFailure,
			Message:  "could not send query to backend",
		}
	}
	var err error
	for {
		if message, length, err = client.TransactionBackend.Receive(); err != nil {
			return false, true, &protocol.Error{
				Severity: protocol.ErrorSeverityFatal,
				Code:     protocol.ErrorCodeConnectionFailure,
				Message:  "could not send query to backend",
			}
		}

		readyFound := false
		var readyStatus transactionStatus

		messageType := protocol.GetMessageType(message[:length])

		// Find the message type of the final message in buffer
		for start := 0; start < length; {
			messageType = protocol.GetMessageType(message[start:])
			messageLength := protocol.GetMessageLength(message[start:])

			/*
			 * Calculate the next start position, add '1' to the message
			 * length to account for the message type.
			 */
			if messageType == protocol.ReadyForQueryMessageType {
				readyFound = true
				readyStatus = transactionStatus(message[start+5])
			}
			start = start + int(messageLength) + 1
		}

		if _, err = client.Send(message[:length]); err != nil {
			return false, true, nil
		}

		if readyFound {
			if readyStatus == txnStatusIdle {
				return true, false, nil
			}
			return false, false, nil
		}
	}
}
