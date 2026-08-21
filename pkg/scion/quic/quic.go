package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsys-lab/panapi/taps"
	"github.com/quic-go/quic-go"
)

type listener struct {
	p *taps.Preconnection
	l *pan.QUICListener
}

type Connection struct {
	*quic.Stream
	p *taps.Preconnection
	*quic.Conn
}

func (c *Connection) Preconnection() *taps.Preconnection {
	return c.p
}

func (c *Connection) Close() error {
	c.Stream.Close()
	return c.Conn.CloseWithError(0, "closed")
}

func (l *listener) Accept() (taps.Connection, error) {
	if l.l == nil {
		return nil, errors.New("not a listener")
	}
	session, err := l.l.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	ep := taps.Endpoint{Address: session.RemoteAddr().String()}
	l.p.RemoteEndpoint = &taps.RemoteEndpoint{Endpoint: ep}
	stream, err := session.AcceptStream(context.Background())
	return &Connection{stream, l.p, session}, err
}

func (l *listener) Close() error {
	return l.l.Close()
}

type Config struct {
	Quic     *quic.Config
	TLS      *tls.Config
	Selector taps.Selector

	// Enables multiple independent, path-pinned QUIC connections when set above 1
	// Needed for path-specific QUIC stats
	// 0 or 1 keeps the existing single-connection behavior unchanged
	MaxPathConnections int
}

type Protocol struct {
	Config Config
}

func (q *Protocol) Selector() taps.Selector {
	return q.Config.Selector
}

func (q *Protocol) Satisfy(p *taps.Preconnection) (*taps.TransportProperties, error) {
	sp := p.TransportPreferences
	var err error
	if sp.Reliability == taps.Prohibit ||
		sp.PreserveOrder == taps.Prohibit ||
		sp.CongestionControl == taps.Prohibit {
		err = errors.New("Can't satisfy all constraints")
	}
	return &taps.TransportProperties{
		Reliability:       true,
		PreserveOrder:     true,
		CongestionControl: true,
		Multipath:         taps.Passive,
	}, err

}

func (q *Protocol) NewListener(p *taps.Preconnection) (taps.Listener, error) {
	_, err := q.Satisfy(p)
	if err != nil {
		return nil, err
	}
	addr, err := pan.ResolveUDPAddr(context.Background(), p.LocalEndpoint.Address)
	if err != nil {
		return nil, err
	}
	if p.ConnectionPreferences != nil {
		err = q.Config.Selector.SetPreferences(p.ConnectionPreferences)
		if err != nil {
			return nil, err
		}
	}
	l, err := pan.ListenQUIC(
		context.Background(),
		netip.AddrPortFrom(addr.IP, addr.Port),
		q.Config.TLS,
		q.Config.Quic,
	)
	return &listener{p: p, l: l}, err
}

// func (q *Protocol) Initiate(p *taps.Preconnection) (taps.Connection, error) {
// 	addr, err := pan.ResolveUDPAddr(context.Background(), p.RemoteEndpoint.Address)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if q.Config.Selector != nil {
// 		err = q.Config.Selector.SetPreferences(p.ConnectionPreferences)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}
// 	session, err := pan.DialQUIC(
// 		context.Background(),
// 		netip.AddrPort{},
// 		addr,
// 		"",
// 		q.Config.TLS,
// 		q.Config.Quic,
// 	)
// 	if err != nil {
// 		return nil, err
// 	}

// 	stream, err := session.OpenStream() //Sync(context.Background())
// 	return &Connection{stream, p, session.Conn}, err

// }

func (q *Protocol) Initiate(p *taps.Preconnection) (taps.Connection, error) {
	if q.Config.MaxPathConnections > 1 {
		return q.initiateMultipath(p)
	}

	addr, err := pan.ResolveUDPAddr(context.Background(), p.RemoteEndpoint.Address)
	if err != nil {
		return nil, err
	}

	var connOptions []pan.ConnOptions
	if q.Config.Selector != nil {
		if p.ConnectionPreferences != nil {
			err = q.Config.Selector.SetPreferences(p.ConnectionPreferences)
			if err != nil {
				return nil, err
			}
		}
		connOptions = append(connOptions, pan.WithSelector(q.Config.Selector))
	}

	session, err := pan.DialQUIC(
		context.Background(),
		netip.AddrPort{},
		addr,
		"",
		q.Config.TLS,
		q.Config.Quic,
		connOptions...,
	)
	if err != nil {
		return nil, err
	}
	stream, err := session.OpenStream()
	return &Connection{stream, p, session.Conn}, err
}
