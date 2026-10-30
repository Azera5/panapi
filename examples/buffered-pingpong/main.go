package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsys-lab/panapi/pkg/convenience"
	"github.com/netsys-lab/panapi/taps"
	"github.com/quic-go/quic-go"

	iquic "github.com/netsys-lab/panapi/pkg/inet/quic"
	tcp "github.com/netsys-lab/panapi/pkg/inet/tcp"
	squic "github.com/netsys-lab/panapi/pkg/scion/quic"
)

type DataUnit string

const (
	UnitB  DataUnit = "B"
	UnitKB DataUnit = "KB"
	UnitMB DataUnit = "MB"
)

var (
	dataSize           int
	dataUnit           DataUnit
	iterations         int
	maxPathConnections int
	useBoundIO         bool
)

func main() {
	var (
		remote, local, t, n, p, dataSizeWithUnit string
		proto                                    taps.Protocol
		server, client                           bool
	)
	flag.StringVar(&remote, "remote", "", `[Client] Remote (i.e. the server's) Address
        (e.g. 17-ffaa:1:1,[127.0.0.1]:1337 or 192.0.2.1:1337, depending on chosen network type)`)
	flag.StringVar(&local, "local", "", `[Server] Local Address to listen on
        (e.g. 17-ffaa:1:1,[127.0.0.1]:1337 or 0.0.0.0:1337, depending on chosen network type)`)
	flag.StringVar(&n, "net", "IP", "network type (IP|SCION)")
	flag.StringVar(&t, "transport", "QUIC", "transport protocol (TCP|QUIC)")
	flag.StringVar(&p, "profile", "", "profile to select ("+taps.Scavenger.String()+"|"+taps.LowLatencyInteractive.String()+")")
	flag.StringVar(&dataSizeWithUnit, "size", "1024B", "size of data (e.g. 50B, 10KB, 5MB)")
	flag.IntVar(&iterations, "iter", 1, "number of iterations (client)")
	flag.IntVar(&maxPathConnections, "max-path-connections", 1, "maximum number of parallel path connections (multipath if > 1)")

	flag.Parse()
	useBoundIO = maxPathConnections > 1

	log.SetFlags(log.Ltime)

	if len(local) > 0 {
		server = true
	}
	if len(remote) > 0 {
		client = true
	}
	if server == client {
		log.Fatalln("Either specify -port for server or -remote for client")
	}

	if t == "TCP" {
		if n == "SCION" {
			log.Fatalln("Transport TCP is not supported for Network Type SCION")
		}
		proto = &tcp.Protocol{}
	} else if t == "QUIC" {
		tlsConf := convenience.DummyTLSConfig()
		if n == "IP" {
			proto = &iquic.Protocol{
				TLSConfig: &tlsConf,
			}
		} else if n == "SCION" {
			var (
				config = &quic.Config{
				KeepAlivePeriod:      10 * time.Second,
			}
				selector taps.Selector
				err      error
			)
			selector, config.Tracer, err = convenience.RPCClientHelper()
			if client {
				if err != nil {
					log.Println(err)
				}
				dataSize, dataUnit, err = parseSize(dataSizeWithUnit)
				if err != nil {
					log.Printf("Error parsing size: %v\n", err)
					return
				}
			}
			proto = &squic.Protocol{
				Config: squic.Config{
					TLS:                &tlsConf,
					Selector:           selector,
					Quic:               config,
					MaxPathConnections: maxPathConnections,
				},
			}
		} else {
			log.Fatalln("Either specify -n IP or -n SCION")
		}
	} else {
		log.Fatalln("Either specify -t TCP or -t QUIC")
	}

	if len(local) > 0 {
		log.Println(runServer(local, proto))
	} else {
		if p == taps.Scavenger.String() {
			log.Println(runClient(remote, proto, taps.Scavenger))
		} else if p == taps.LowLatencyInteractive.String() {
			log.Println(runClient(remote, proto, taps.LowLatencyInteractive))
		} else {
			log.Println(runClient(remote, proto, taps.Default))
		}
	}
}

func serverWorker(idx int, conn taps.Connection) {
	remote := "unknown"
	if a, ok := conn.(interface{ RemoteAddr() net.Addr }); ok {
		remote = a.RemoteAddr().String()
	}
	fmt.Printf("Server Worker #%d started (remote=%s)\n", idx, remote)
	defer conn.Close()
	r := bufio.NewReader(conn)

	var lastMsg atomic.Value
	lastMsg.Store(time.Now())

	stop := make(chan struct{})
	defer close(stop)

	break_counter := 0
	for {
		fullData, err := r.ReadBytes(0x04)

		if err != nil && err != io.EOF {
			fmt.Printf("[worker #%d] Read error: %s\n", idx, err)
			break_counter++
			if break_counter > 5 {
				break
			}
			continue
		}
		lastMsg.Store(time.Now())
		bufferSize := int64(len(fullData))
		msg := string(bytes.SplitN(fullData, []byte("\n"), 2)[0])
		bufferInUnit, unit, err := getBufferInUnit(msg, bufferSize)
		fmt.Printf("[worker #%d] Received Msg: %s Buffersize: %.2f %s\n", idx, msg, bufferInUnit, unit)

		if _, err := conn.Write([]byte("\n")); err != nil {
			log.Printf("[worker #%d] Write error: %s\n", idx, err)
			break_counter++
			if break_counter > 5 {
				break
			}
			continue
		}
	}
}

type boundReader struct {
	bound squic.BoundReadWriter
	id    any
}

func (r boundReader) Read(p []byte) (int, error) {
	return r.bound.ReadBound(r.id, p)
}

func write(conn taps.Connection, bound squic.BoundReadWriter, id any, data []byte) (int, error) {
	if !useBoundIO {
		return conn.Write(data)
	}
	n, err := bound.WriteBound(id, data)
	if err != nil {
		bound.RemoveBound(id)
	}
	return n, err
}

func read(r *bufio.Reader, bound squic.BoundReadWriter, id any) (string, error) {
	if !useBoundIO {
		return r.ReadString('\n')
	}
	r.Reset(boundReader{bound, id})
	s, err := r.ReadString('\n')
	bound.RemoveBound(id)
	return s, err
}

func clientWorker(pconn taps.Preconnection) {
	conn, err := pconn.Initiate()
	if err != nil {
		log.Printf("Client error: %v", err)
		return
	}
	defer conn.Close()

	var bound squic.BoundReadWriter
	if useBoundIO {
		bound = conn.(squic.BoundReadWriter)
	}
	r := bufio.NewReader(conn)
	globalStart := time.Now()
	errorCounter := 0
	for i := 0; i < iterations; i++ {
		gotError := false
		msg := fmt.Sprintf("Iteration %d: %s # %d %s\n", i, time.Now().Format(time.RFC3339Nano), dataSize, dataUnit)
		bufferSize := sizeToBytes(dataSize, dataUnit)
		if bufferSize < len(msg)+1 {
			fmt.Printf("buffer size (%d bytes) too small for message (%d bytes)", bufferSize, len(msg))
			return
		}
		data := make([]byte, bufferSize)
		copy(data, msg)
		data[bufferSize-1] = 0x04

		start := time.Now()
		var id = i 

		if _, err = write(conn, bound, id, data); err != nil {
			fmt.Println(err)
			gotError = true
		}

		if _, err = read(r, bound, id); err != nil {
			fmt.Printf("ERROR WHILE READING: %s\n", err)
			gotError = true
		}

		if gotError {
			errorCounter++
		} else {
			rtt := time.Since(start)
			fmt.Printf("Msg: %s: RTT=%v\n", strings.TrimSuffix(msg, "\n"), rtt)
		}
	}
	fmt.Printf("Finished in: %v with %d errors\n", time.Since(globalStart), errorCounter)

}

func runServer(local string, proto taps.Protocol) error {
	LocalSpecifier := taps.LocalEndpoint{}
	LocalSpecifier.Address = local
	LocalSpecifier.Protocol = proto

	Preconnection := taps.Preconnection{LocalEndpoint: &LocalSpecifier}

	Listener, err := Preconnection.Listen()
	if err != nil {
		return err
	}

	var idx atomic.Int64
	var wg sync.WaitGroup
	for a := 0; a < maxPathConnections; a++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, err := Listener.Accept()
				if err != nil {
					log.Println(err)
					continue
				}
				i := int(idx.Add(1) - 1)
				log.Printf("Got connection, assigning worker #%d", i)
				go serverWorker(i, conn)
			}
		}()
	}
	wg.Wait()
	return nil
}

func runClient(remote string, proto taps.Protocol, profile taps.CapacityProfile) error {
	RemoteSpecifier := taps.RemoteEndpoint{}
	RemoteSpecifier.Address = remote
	RemoteSpecifier.Protocol = proto
	Preconnection := taps.Preconnection{
		RemoteEndpoint: &RemoteSpecifier,
		ConnectionPreferences: &taps.ConnectionPreferences{
			ConnCapacityProfile: profile,
		},
	}

	clientWorker(Preconnection)

	return nil

}

// helper functions
func parseSize(s string) (int, DataUnit, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, "", fmt.Errorf("empty size")
	}

	var unit DataUnit
	var num string

	switch {
	case strings.HasSuffix(s, "MB"):
		unit, num = UnitMB, strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		unit, num = UnitKB, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		unit, num = UnitB, strings.TrimSuffix(s, "B")
	default:
		return 0, "", fmt.Errorf("invalid unit (B, KB, MB)")
	}

	size, err := strconv.Atoi(strings.TrimSpace(num))
	if err != nil || size < 0 {
		return 0, "", fmt.Errorf("invalid number")
	}

	return size, unit, nil
}

func getBufferInUnit(msg string, bufferBytes int64) (float64, DataUnit, error) {
	_, unit, err := parseSizeFromMessage(msg)
	if err != nil {
		return 0, "", err
	}

	switch unit {
	case UnitKB:
		return float64(bufferBytes) / 1024, unit, nil
	case UnitMB:
		return float64(bufferBytes) / (1024 * 1024), unit, nil
	default:
		return float64(bufferBytes), unit, nil
	}
}

func parseSizeFromMessage(msg string) (int, DataUnit, error) {
	parts := strings.SplitN(msg, "#", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid message format: missing #")
	}

	sizePart := strings.TrimSpace(strings.SplitN(parts[1], "\n", 2)[0])
	return parseSize(sizePart)
}

func sizeToBytes(size int, unit DataUnit) int {
	switch unit {
	case UnitKB:
		return size * 1024
	case UnitMB:
		return size * 1024 * 1024
	default:
		return size
	}
}
