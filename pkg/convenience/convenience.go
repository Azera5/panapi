package convenience

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"

	"github.com/netsys-lab/panapi/rpc"
	"github.com/netsys-lab/panapi/taps"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

func GenerateTLSConfig() tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
}

func DummyTLSConfig() tls.Config {
	conf := GenerateTLSConfig()
	conf.NextProtos = []string{"dummy-test"}
	conf.InsecureSkipVerify = true
	return conf
}

func NewRPCClient() (*rpc.Client, error) {
	conn, err := net.Dial(rpc.DefaultDaemonAddress.Net, rpc.DefaultDaemonAddress.Name)
	if err != nil {
		return nil, err
	}
	return rpc.NewClient(conn)
}

// func RPCClientHelper() (selector taps.Selector, tracer func(context.Context, logging.Perspective, logging.ConnectionID) *logging.ConnectionTracer, err error) {
// 	c, err := NewRPCClient()
// 	if err != nil {
// 		return
// 	}
// 	selector = rpc.NewSelectorClient(c)
// 	tracer = rpc.NewTracerForConnection(c)
// 	return
// }

func RPCClientHelper() (selector taps.Selector, tracerFunc func(context.Context, logging.Perspective, logging.ConnectionID) *logging.ConnectionTracer,
	err error,
) {
	c, err := NewRPCClient()
	if err != nil {
		return
	}
	selector = rpc.NewSelectorClient(c)
	// Temporary workaround: tracer runs locally because of an error: "connection_tracer.go:169: gob: type protocol.ConnectionID has no exported fields"
	tracerFunc = func(ctx context.Context, p logging.Perspective, connID logging.ConnectionID) *logging.ConnectionTracer {
		fname := fmt.Sprintf("/tmp/quic-tracer-%d-%x.qlog", p, connID)
		log.Println("quic tracer file opened as", fname)
		f, err := os.Create(fname)
		if err != nil {
			panic(err)
		}
		return qlog.NewConnectionTracer(f, p, connID)
	}
	return
}
