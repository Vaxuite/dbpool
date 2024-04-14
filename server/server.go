package server

import (
	"github.com/Vaxuite/dbpool/proxy"
	"github.com/sirupsen/logrus"
	"net"
	"strconv"
	"sync"
)

var (
	log = logrus.New()
)

type Config struct {
	Port int
}

type Server struct {
	waitGroup *sync.WaitGroup
	config    Config
	ch        chan bool
	p         *proxy.Proxy
	listener  net.Listener
}

func NewServer(config Config, p *proxy.Proxy) *Server {
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
	proxyListener, err := net.Listen("tcp", ":"+strconv.Itoa(s.config.Port))
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

		go s.p.HandleConnection(proxy.NewClient(conn))
	}
}

func (s *Server) Stop() {
	s.listener.Close()
	close(s.ch)
}
