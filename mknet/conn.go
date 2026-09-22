package mknet

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// ReadHostfile parses a hostfile with one "ip:port" entry per line, in party
// order: line i is party i+1's listen address. Empty lines and #-comments are
// skipped.
func ReadHostfile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, err := net.SplitHostPort(line); err != nil {
			return nil, fmt.Errorf("%s:%d: bad host entry %q (want ip:port)", path, i+1, line)
		}
		hosts = append(hosts, line)
	}
	if len(hosts) != 2 {
		return nil, fmt.Errorf("%s: want exactly 2 host entries (one per party), got %d", path, len(hosts))
	}
	return hosts, nil
}

// CountingConn wraps a net.Conn and counts the bytes actually sent/received
// over the socket, so the session can report measured (not analytic)
// communication volumes.
type CountingConn struct {
	net.Conn
	sent atomic.Uint64
	recv atomic.Uint64
}

func (c *CountingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.sent.Add(uint64(n))
	return n, err
}

func (c *CountingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.recv.Add(uint64(n))
	return n, err
}

func (c *CountingConn) SentBytes() uint64 { return c.sent.Load() }
func (c *CountingConn) RecvBytes() uint64 { return c.recv.Load() }

// connectTimeout bounds how long the parties may wait for each other.
const connectTimeout = 120 * time.Second

// Connect establishes the party-to-party TCP connection. Both parties listen
// on their own hostfile entry AND dial the peer's, so either process may be
// started first; the deterministic tie-break keeps them on the same pipe:
// the connection INITIATED BY PARTY 1 wins (party 1 uses its dial result,
// party 2 uses its accepted connection, everything else is closed).
func Connect(hosts []string, selfIdx int) (*CountingConn, error) {
	if selfIdx != 1 && selfIdx != 2 {
		return nil, fmt.Errorf("mknet: party index must be 1 or 2, got %d", selfIdx)
	}
	selfAddr := hosts[selfIdx-1]
	peerAddr := hosts[2-selfIdx]

	ln, err := net.Listen("tcp", selfAddr)
	if err != nil {
		return nil, fmt.Errorf("mknet: listen on %s: %w", selfAddr, err)
	}

	accepted := make(chan net.Conn, 1)
	dialed := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	go func() {
		deadline := time.Now().Add(connectTimeout)
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp", peerAddr, 5*time.Second)
			if err == nil {
				dialed <- conn
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()

	var conn net.Conn
	if selfIdx == 1 {
		select {
		case conn = <-dialed:
		case <-time.After(connectTimeout):
			ln.Close()
			return nil, fmt.Errorf("mknet: cannot reach party 2 at %s within %v", peerAddr, connectTimeout)
		}
	} else {
		select {
		case conn = <-accepted:
		case <-time.After(connectTimeout):
			ln.Close()
			return nil, fmt.Errorf("mknet: party 2: no incoming connection within %v", connectTimeout)
		}
	}
	ln.Close()

	// Drain and close the loser connection (the one the peer initiated) even
	// if it lands after the race above; the drainer goroutine may block
	// forever when nothing arrives, which is harmless for a session process.
	go func() {
		var spare net.Conn
		if selfIdx == 1 {
			spare = <-accepted
		} else {
			spare = <-dialed
		}
		if spare != nil {
			spare.Close()
		}
	}()

	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetNoDelay(false) // bulk transfers: let Nagle/batching work
	}
	return &CountingConn{Conn: conn}, nil
}

// framedConn pairs a CountingConn with buffered reading for frame decoding.
type framedConn struct {
	conn *CountingConn
	r    *bufio.Reader
}

func newFramedConn(conn *CountingConn) *framedConn {
	return &framedConn{conn: conn, r: bufio.NewReaderSize(conn, 1<<20)}
}

func (fc *framedConn) write(msgType byte, payload []byte) error {
	return WriteMsg(fc.conn, msgType, payload)
}

func (fc *framedConn) read() (byte, []byte, error) {
	return ReadMsg(fc.r)
}
