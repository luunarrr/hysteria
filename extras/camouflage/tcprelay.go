package camouflage

import (
	"io"
	"net"
	"sync"
	"time"
)

const (
	tcpRelayDialTimeout = 10 * time.Second
)

// TCPRelay transparently relays all TCP connections to a real destination.
// No TLS termination, no parsing -- fully opaque byte copy.
type TCPRelay struct {
	listenAddr string
	destAddr   string
	listener   net.Listener

	closeOnce sync.Once
	done      chan struct{}
}

// NewTCPRelay creates a TCP relay that listens on listenAddr and relays
// every accepted connection to destAddr.
func NewTCPRelay(listenAddr, destAddr string) *TCPRelay {
	return &TCPRelay{
		listenAddr: listenAddr,
		destAddr:   destAddr,
		done:       make(chan struct{}),
	}
}

// Serve starts listening and relaying. Blocks until Close is called or an
// unrecoverable error occurs.
func (r *TCPRelay) Serve() error {
	ln, err := net.Listen("tcp", r.listenAddr)
	if err != nil {
		return err
	}
	r.listener = ln

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-r.done:
				return nil
			default:
				return err
			}
		}
		go r.handleConn(conn)
	}
}

func (r *TCPRelay) handleConn(client net.Conn) {
	defer client.Close()

	upstream, err := net.DialTimeout("tcp", r.destAddr, tcpRelayDialTimeout)
	if err != nil {
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		_ = upstream.(*net.TCPConn).CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		_ = client.(*net.TCPConn).CloseWrite()
	}()
	wg.Wait()
}

// Close stops the TCP relay.
func (r *TCPRelay) Close() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.done)
		if r.listener != nil {
			err = r.listener.Close()
		}
	})
	return err
}
