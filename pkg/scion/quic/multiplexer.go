package quic

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsys-lab/panapi/rpc"
	"github.com/netsys-lab/panapi/taps"
	"github.com/quic-go/quic-go"
)

// Prevents stuck dials from hanging indefinitely and blocking Close()
const backgroundDialTimeout = 10 * time.Second

// How often the daemon-side selector is polled to (re)select the active pinned path.
const activePathPollInterval = 1 * time.Second

// Defines how many consecutive duplicates cause the grow pool process to stop
const maxConsecutiveDuplicateDials = 3

// A path-specific QUIC connection inside a MultiConnection's pool
type pinnedConn struct {
	conn      *quic.Conn
	stream    *quic.Stream
	selClient *rpc.SelectorClient
	local     pan.UDPAddr
	fp        pan.PathFingerprint
}

// To manage a pool of path-specific connections
type MultiConnection struct {
	p         *taps.Preconnection
	protocol  *Protocol
	remote    pan.UDPAddr
	rpcClient *rpc.Client // shared RPC connection, used to poll SelectActivePath

	mu     sync.Mutex
	conns  []*pinnedConn
	closed bool
	active *pinnedConn

	done chan struct{}  // closed by Close() to stop pollActivePath
	wg   sync.WaitGroup // Tracks growPool/pollActivePath so Close can wait for them to fully exit before returning
}

func (mc *MultiConnection) Preconnection() *taps.Preconnection {
	return mc.p
}

func (mc *MultiConnection) Write(p []byte) (int, error) {
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c := mc.pickActiveLocked()
	mc.mu.Unlock()

	if c == nil {
		return 0, errors.New("quic: MultiConnection has no pinned connections")
	}
	return c.stream.Write(p)
}

func (mc *MultiConnection) pickActiveLocked() *pinnedConn {
	if len(mc.conns) == 0 {
		mc.active = nil
		return nil
	}
	if mc.active != nil {
		for _, c := range mc.conns {
			if c == mc.active {
				return mc.active
			}
		}
	}
	mc.active = mc.conns[0]
	return mc.active
}

func (mc *MultiConnection) Read(p []byte) (int, error) {
	mc.mu.Lock()
	active := mc.active
	mc.mu.Unlock()

	if active == nil {
		return 0, errors.New("quic: MultiConnection: Read called before any Write")
	}
	return active.stream.Read(p)
}

func (mc *MultiConnection) Close() error {
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return nil
	}
	mc.closed = true
	conns := mc.conns
	mc.conns = nil
	mc.active = nil
	mc.mu.Unlock()

	close(mc.done)
	mc.wg.Wait()

	var firstErr error
	for _, c := range conns {
		if err := discardDial(c); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Sets up the first connection synchronously, then grows the pool in the background
func (q *Protocol) initiateMultipath(p *taps.Preconnection) (taps.Connection, error) {
	addr, err := pan.ResolveUDPAddr(context.Background(), p.RemoteEndpoint.Address)
	if err != nil {
		return nil, err
	}

	sc, ok := q.Config.Selector.(*rpc.SelectorClient)
	if !ok {
		return nil, errors.New("quic: MaxPathConnections > 1 requires an *rpc.SelectorClient Selector")
	}

	mc := &MultiConnection{
		p:         p,
		protocol:  q,
		remote:    addr,
		rpcClient: sc.RPCClient(),
		done:      make(chan struct{}),
	}

	first, err := mc.dialOne(context.Background())
	if err != nil {
		return nil, err
	}
	mc.conns = append(mc.conns, first)

	mc.wg.Add(1)
	go mc.growPool()

	mc.wg.Add(1)
	go mc.pollActivePath()

	return mc, nil
}

// Periodically checks which path should be active
func (mc *MultiConnection) pollActivePath() {
	defer mc.wg.Done()

	ticker := time.NewTicker(activePathPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mc.done:
			return
		case <-ticker.C:
			mc.pollActivePathOnce()
		}
	}
}

func (mc *MultiConnection) pollActivePathOnce() {
	mc.mu.Lock()
	if mc.closed || len(mc.conns) == 0 {
		mc.mu.Unlock()
		return
	}
	current := make([]pan.PathFingerprint, len(mc.conns))
	for i, c := range mc.conns {
		current[i] = c.fp
	}
	mc.mu.Unlock()

	fp, err := mc.rpcClient.SelectActivePath(mc.remote, current)
	if err != nil || fp == "" {
		return
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()
	for _, c := range mc.conns {
		if c.fp == fp {
			mc.active = c
			return
		}
	}
}

// Creates and pins a new connection using a fresh Selector instance
func (mc *MultiConnection) dialOne(ctx context.Context) (*pinnedConn, error) {
	q := mc.protocol

	inner := rpc.NewSelectorClient(mc.rpcClient)
	sel := NewPinnedSelector(inner)
	selClient, _ := inner.(*rpc.SelectorClient)

	session, err := pan.DialQUIC(
		ctx,
		netip.AddrPort{},
		mc.remote,
		"",
		q.Config.TLS,
		q.Config.Quic,
		pan.WithSelector(sel),
	)
	if err != nil {
		return nil, err
	}
	stream, err := session.OpenStream()
	if err != nil {
		session.CloseWithError(0, "stream open failed")
		return nil, err
	}

	local, ok := session.LocalAddr().(pan.UDPAddr)
	if !ok {
		session.CloseWithError(0, "unexpected local address type")
		return nil, errors.New("quic: pan connection did not return a pan.UDPAddr local address")
	}
	fp, _ := sel.PinnedFingerprint()

	return &pinnedConn{
		conn:      session.Conn,
		stream:    stream,
		selClient: selClient,
		local:     local,
		fp:        fp,
	}, nil
}

// Returns the target pool size based on the configured limit and available paths
func (mc *MultiConnection) targetPoolSize() int {
	target := mc.protocol.Config.MaxPathConnections
	paths, err := pan.QueryPaths(context.Background(), mc.remote.IA)
	if err != nil {
		return target
	}
	if len(paths) < target {
		return len(paths)
	}
	return target
}

// Adds new connections with distinct paths until the pool is full
func (mc *MultiConnection) growPool() {
	defer mc.wg.Done()

	target := mc.targetPoolSize()
	consecutiveDuplicates := 0

	for {
		mc.mu.Lock()
		n := len(mc.conns)
		closed := mc.closed
		mc.mu.Unlock()
		if closed || n >= target {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), backgroundDialTimeout)
		c, err := mc.dialOne(ctx)
		cancel()
		if err != nil {
			return
		}

		mc.mu.Lock()
		if mc.closed {
			mc.mu.Unlock()
			discardDial(c)
			return
		}
		duplicate := false
		for _, existing := range mc.conns {
			if existing.fp == c.fp {
				duplicate = true
				break
			}
		}
		if !duplicate {
			mc.conns = append(mc.conns, c)
			consecutiveDuplicates = 0
			mc.mu.Unlock()
			continue
		}
		mc.mu.Unlock()

		discardDial(c)
		consecutiveDuplicates++
		if consecutiveDuplicates >= maxConsecutiveDuplicateDials {
			return
		}
	}
}

// Cleans up a connection that is no longer needed, including daemon-side state.
func discardDial(c *pinnedConn) error {
	if c.selClient != nil {
		c.selClient.NotifyClosed()
	}
	return c.conn.CloseWithError(0, "closed")
}