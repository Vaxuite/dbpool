package server

import (
	"github.com/Vaxuite/dbpool/network"
	"github.com/sirupsen/logrus"
	"net"
	"strconv"
	"sync"
)

var (
	log = logrus.New()
)

type Config struct {
	Host string
	Port int
}

type Proxy interface {
	HandleConnection(client *network.Client) error
}

type Server struct {
	waitGroup *sync.WaitGroup
	config    Config
	ch        chan bool
	p         Proxy
	listener  net.Listener
}

func NewServer(config Config, p Proxy) *Server {
	s := &Server{
		config:    config,
		waitGroup: &sync.WaitGroup{},
		ch:        make(chan bool),
		p:         p,
	}

	return s
}

func (s *Server) Start() error {
	log.Info("Proxy Server Starting...")
	proxyListener, err := net.Listen("tcp", s.config.Host+":"+strconv.Itoa(s.config.Port))
	if err != nil {
		return err
	}

	s.waitGroup.Add(1)
	go func() {
		if err := s.Serve(proxyListener); err != nil {
			log.WithError(err).Panic("failed to serve proxy")
		}
	}()

	s.waitGroup.Wait()

	log.Info("Server Exiting...")
	return nil
}

func (s *Server) Serve(l net.Listener) error {
	log.Infof("Proxy Server listening on: %s", l.Addr())
	defer s.waitGroup.Done()
	s.listener = l

	for {

		select {
		case <-s.ch:
			return nil
		default:
		}

		conn, err := l.Accept()

		if err != nil {
			continue
		}

		go func() {
			if err := s.p.HandleConnection(network.NewClient(conn)); err != nil {
				if err := conn.Close(); err != nil {
					log.WithError(err).Warn("failed to close connection")
				}
			}
		}()
	}
}

func (s *Server) Stop() {
	s.listener.Close()
	close(s.ch)
}
