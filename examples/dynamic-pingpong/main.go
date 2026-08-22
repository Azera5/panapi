package main

import (
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"time"

	"github.com/netsys-lab/panapi/pkg/convenience"
	"github.com/netsys-lab/panapi/taps"
	"github.com/quic-go/quic-go"

	flags "github.com/jessevdk/go-flags"
	iquic "github.com/netsys-lab/panapi/pkg/inet/quic"
	tcp "github.com/netsys-lab/panapi/pkg/inet/tcp"
	squic "github.com/netsys-lab/panapi/pkg/scion/quic"
)

var opts struct {
	Verbose             bool    `short:"v" long:"verbose" description:"Show verbose debug information"`
	Server              bool    `short:"s" long:"server" description:"Run in server mode (receive)"`
	Reciprocity         bool    `short:"r" long:"reciprocity" description:"If true both server and client are sending and recieving"`
	Acceleration        bool    `short:"a" long:"acceleration" description:"Scales the interval length with (sin(#iteration * 15°) + 1) * 0.5"`
	Order               bool    `short:"o" long:"check-order" description:"Checks wether the waves are recieved in the correct order"`
	UndoDrops           bool    `short:"u" long:"undo-drops" description:"Assuming the reciprocity mode the server tries to reconstruct missing/dropped waves derived from successful transmissions"`
	Client              string  `short:"c" long:"client" description:"Remote SCION address to connect to (client/send mode)"`
	LocalAddr           string  `short:"l" long:"local" description:"Local SCION address, e.g. 1-ff00:0:1,[127.0.0.1]:8080, if unset uses the output of 'scion address' with port 1337"`
	Bytes               uint64  `short:"n" long:"bytes" default:"0" description:"Total bytes to send; no limit if 0"`
	BufferSize          int     `short:"b" long:"buffer-size" default:"1400" description:"Send/receive buffer size in bytes"`
	Duration            int     `short:"t" long:"duration" default:"10" description:"Test duration in seconds (client mode)"`
	AccelerationDegree  int     `short:"d" long:"degree" default:"15" description:"Changes the default step size for the acceleration: smoother transitions with values lower than 15 and de-facto disabled acceleration for multiples of 180 (e.g. 360 and so on)"`
	Interval            float64 `short:"i" long:"interval" default:"1.0" description:"Iteration interval in seconds (float)"`
	MinInterval         float64 `long:"min-interval" default:"0.0" description:"Lower bound for the iteration interval in seconds (float), when -a is chosen; no limit if 0.0"`
	NumWaves            int     `long:"num-waves" default:"1" description:"Number of read-write waves within a single interval"`
	MaxIterations       int     `long:"max-iterations" default:"0" description:"Limiting the interactions between client und server; no limit if 0"`
	BufferPrintSize     int     `long:"buffer-print-size" default:"32" description:"How many characters should be printed, in order to illustrate the buffer content, default is 32"`
	AllowedReadAttempts int     `long:"allowed-read-attempts" default:"3" description:"Defines how many times the read wrapper tries to read the recieved message; 0 means no limit; only relevant without --simple-read"`
	NetworkProtocol     string  `long:"network-protocol" default:"0" description:" ...: IP|SCION"`
	TransportProtocol   string  `long:"transport-protocol" default:"0" description:" ...: TCP|QUIC"`
	Profile             string  `long:"profile" default:"0" description:" ..."`
	NoReadOffset        bool    `long:"no-read-offset" description:"Don't use partial and interrupted transmissions for read offsets; only relevant without --simple-read"`
	SimpleCorrection    bool    `long:"simple-correction" description:"Don't use  information from past iterations to correct current dropped transfers; only relevant with -u/--undo-drops"`
	SimpleRead          bool    `long:"simple-read" description:"Use a simple one write one read scheme, no correcting offsets and timeouts"`
}

func printf(format string, args ...any) {
	if len(args) == 0 {
		fmt.Print(format)
	} else {
		fmt.Printf(format, args...)
	}
}

func readAdvanced(bufs map[int][]byte, conn taps.Connection, i int, server bool) (int, int, bool) {
	timeout := time.Duration(int64(opts.Interval*1000000000/float64(opts.NumWaves))) * time.Nanosecond
	currentReadAttempts, currentReadBytes, currentReadBytesSum, usedBufferOffset := 1, 0, 0, 0
	validState := false
	var err error

	type resultStruct struct {
		currentReadBytes int
		err              error
	}
	ch := make(chan resultStruct)

	for r := 1; !validState; r++ {
		// resetting buffers
		for b := 0; b < opts.BufferSize; b++ {
			bufs[i][b] = byte('0')
		}

		if opts.NoReadOffset {
			usedBufferOffset = 0
		} else {
			usedBufferOffset = currentReadBytesSum
		}

		// attempting to read
		// basic timeout pattern is adapted from:
		// https://stackoverflow.com/questions/68748342/using-context-to-share-a-common-timeout-across-consecutive-function-calls
		go func() {
			currentReadBytes, err := conn.Read(bufs[i][usedBufferOffset:])
			ch <- resultStruct{currentReadBytes, err}
		}()

		select {
		case <-time.After(timeout):
			if opts.Verbose {
				if server {
					log.Println("<SERVER> %d. read attempt timeout after %fs ...", currentReadAttempts, timeout.Seconds())
				} else {
					log.Println("<CLIENT> %d. read attempt timeout after %fs ...", currentReadAttempts, timeout.Seconds())
				}
			}
			currentReadBytes = 0
			err = nil
		case result := <-ch:
			currentReadBytes = result.currentReadBytes
			err = result.err
		}
		if err != nil {
			log.Fatal(err.Error())
		}

		currentReadAttempts = r
		currentReadBytesSum = currentReadBytesSum + currentReadBytes

		// evaluating if the read was successful
		if currentReadBytesSum == opts.BufferSize && bufs[i][0] == byte('#') {
			// we assume the prefix is correct...
			validState = true
			// ...and check if it's actually true (if required via -o flag)
			for b := 0; b < 1+i && opts.Order; b++ {
				if bufs[i][b] != byte('#') {
					validState = false
				}
			}
		}

		if currentReadAttempts >= opts.AllowedReadAttempts {
			return currentReadAttempts, currentReadBytes, validState
		}
	}

	return currentReadAttempts, currentReadBytesSum, validState
}

func readSimple(bufs map[int][]byte, conn taps.Connection, i int) (int, int, bool) {
	validState := false

	currentReadBytes, err := conn.Read(bufs[i])
	if err != nil {
		log.Fatal(err.Error())
	}

	// evaluating if the read was successful
	if currentReadBytes == opts.BufferSize && bufs[i][0] == byte('#') {
		// we assume the prefix is correct...
		validState = true
		// ...and check if it's actually true (if required via -o flag)
		for b := 0; b < 1+i && opts.Order; b++ {
			if bufs[i][b] != byte('#') {
				validState = false
			}
		}
	}

	return 1, currentReadBytes, validState
}

func calcWaitTime(itrcounter int) (float64, float64) {
	acclerationFactor := 0.0
	if opts.Acceleration {
		acclerationFactor = (math.Sin(float64(itrcounter)*float64(opts.AccelerationDegree)*math.Pi/180) + 1) * 0.5
		// math.Sin takes radians as arg not degrees! => math.Pi/180 is the conversion; default step: 15°, otherwise whatever the AccelerationDegree is
		// also: halfIntervalTime will be often scaled by 1000000000 (one billion) in order to represent nanoseconds within time.Duration, e.g. for fractioned wait time between waves
		return math.Max(opts.MinInterval/2, (opts.Interval/2)*acclerationFactor), acclerationFactor
	} else {
		return (opts.Interval / 2), 1.0
	}
}

func main() {

	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	if !opts.Server && opts.Client == "" {
		fmt.Fprintln(os.Stderr, "error: specify -s (server) or -c ADDR (client)")
		os.Exit(1)
	}
	if opts.Server && opts.Client != "" {
		fmt.Fprintln(os.Stderr, "error: -s and -c are mutually exclusive")
		os.Exit(1)
	}
	if opts.LocalAddr == "" {
		cmdStruct := exec.Command("scion", "address")
		out, err := cmdStruct.Output()
		opts.LocalAddr = string(out)[:len(out)-1] + ":1337"
		if err != nil {
			fmt.Println(err)
		}
	}
	//printf("\n\n adr: %s", opts.LocalAddr)
	//os.Exit(0)
	if opts.BufferSize < 1 {
		fmt.Fprintln(os.Stderr, "error: --buffer-size must be >= 1")
		os.Exit(1)
	}
	if opts.Interval <= 0.0 {
		fmt.Fprintln(os.Stderr, "error: --interval must be >= 0")
		os.Exit(1)
	}
	if opts.Interval < opts.MinInterval {
		fmt.Fprintln(os.Stderr, "error: --interval must be >= --min-interval")
		os.Exit(1)
	}
	if opts.MaxIterations <= 0 {
		opts.MaxIterations = math.MaxInt
	}
	if opts.AllowedReadAttempts <= 0 {
		opts.AllowedReadAttempts = math.MaxInt
	}
	if opts.NumWaves <= 0 {
		printf("\n\n <INFO> the amount of send-waves should be >=1 but isn't: %d, it will be set to 1 (default)!", opts.NumWaves)
		opts.NumWaves = 1

	}
	if opts.Bytes == 0 {
		opts.Bytes = math.MaxUint64
	}

	var proto taps.Protocol
	var capacity taps.CapacityProfile
	var startLoop, startRead, startWrite time.Time
	var loopDelta, deltaWrite, deltaRead time.Duration

	itrcounter := 0
	halfIntervalTime := 0.0

	if opts.TransportProtocol == "TCP" {
		if opts.NetworkProtocol == "SCION" {
			log.Fatalln("Transport TCP is not supported for Network Type SCION")
		}
		proto = &tcp.Protocol{}
	} else if opts.TransportProtocol == "QUIC" {
		tlsConf := convenience.DummyTLSConfig()
		if opts.NetworkProtocol == "IP" {
			proto = &iquic.Protocol{
				TLSConfig: &tlsConf,
			}
		} else if opts.NetworkProtocol == "SCION" {
			var (
				config   = &quic.Config{}
				selector taps.Selector
				err      error
			)
			if !opts.Server {
				selector, config.Tracer, err = convenience.RPCClientHelper()
				// var tracerFunc func(context.Context, logging.Perspective, logging.ConnectionID) *logging.ConnectionTracer
				// selector, tracerFunc, err = convenience.RPCClientHelper()
				if err != nil {
					log.Println(err.Error())
				}
				// config.Tracer = tracerFunc
			}
			proto = &squic.Protocol{
				squic.Config{
					TLS:      &tlsConf,
					Selector: selector,
					Quic:     config,
				},
			}
		} else {
			log.Fatalln("Either specify --network-protocol IP or --network-protocol SCION")
		}
	} else {
		log.Fatalln("Either specify --transport-protocol TCP or --transport-protocol QUIC")
	}

	if opts.Server {

		startServer := time.Now()
		LocalSpecifier := taps.LocalEndpoint{}
		LocalSpecifier.Address = opts.LocalAddr
		LocalSpecifier.Protocol = proto

		Preconnection := taps.Preconnection{
			LocalEndpoint: &LocalSpecifier,
		}

		Listener, errPrecon := Preconnection.Listen()
		if errPrecon != nil {
			log.Println(errPrecon.Error())
		}

		var conn taps.Connection
		var err error
		for {
			conn, err = Listener.Accept()
			if err != nil {
				log.Fatal(err.Error())
			} else {
				log.Println("<SERVER> Connection established")
				break
			}
		}

		bufs := make(map[int][]byte)
		var totalRead, totalSent, totalDropped uint64 = 0, 0, 0
		mainbuf := make([]byte, opts.BufferSize)
		mainbuf[0] = byte('[')
		mainbuf[opts.NumWaves+1] = byte(']')

		for i := 0; i < opts.NumWaves; i++ {
			bufs[i] = make([]byte, opts.BufferSize)

			// fill with (literal) zeros
			for b := 0; b < opts.BufferSize; b++ {
				bufs[i][b] = byte('0')
			}
			// init with (effectivly) with A,B,C,... but with -1 (e.g. A as 64 rather than 65) because the main loop increments with 1
			bufs[i][1+i] = byte(64 + (i % 26))

		}

		for {
			startLoop = time.Now()
			var sentBytes, readBytes, countedDrops, countedCorrections uint64
			var currentReadAttempts, currentReadBytesSum int
			var validState bool
			var sentMbps, readMbps, acclerationFactor float64
			halfIntervalTime, acclerationFactor = calcWaitTime(itrcounter)

			totalReadAttempts := 0
			countedDrops, countedCorrections = 0, 0
			itrcounter++
			for i := 0; i < opts.NumWaves; i++ {

				startRead = time.Now()
				if opts.SimpleRead {
					currentReadAttempts, currentReadBytesSum, validState = readSimple(bufs, conn, i)
				} else {
					currentReadAttempts, currentReadBytesSum, validState = readAdvanced(bufs, conn, i, true)
				}
				deltaRead = time.Since(startRead)
				readBytes = readBytes + uint64(currentReadBytesSum)
				totalReadAttempts = totalReadAttempts + currentReadAttempts

				if opts.Verbose {
					if validState {
						log.Println("<SERVER> Iteration:", itrcounter, " read ", currentReadBytesSum, " read bytes in ", currentReadAttempts, " read-attempts via wave ", i, " - ", string(bufs[i])[:opts.BufferPrintSize])
					} else {
						log.Println("<SERVER> Iteration:", itrcounter, " dropped after ", currentReadBytesSum, " read bytes in ", currentReadAttempts, " read-attempts via wave ", i, " - ", string(bufs[i])[:opts.BufferPrintSize])
					}

				}

				// failed/dropped reads will be shown with underscores
				if !validState {
					for b := 1 + i; b < opts.BufferSize; b++ {
						bufs[i][b] = byte('_')
					}
				}

				if bufs[i][1+i] != byte('_') {
					// every stream manages one particular character and its incrementation
					//01234   x       <---- indices for mainbuffer (server) and send/recieve-buffer (server AND client); the mainbuffer ends with ']' at index opts.NumWaves (x)
					//[ABCD...]       <---- example for the first timestep); [BCDE...] second timestep etc. (mainbuffer / server perspective)
					// |||
					//#AAAAAAAA...
					//  ||
					//##BBBBBBB...    <---- only ONE index is overwritten with the character-sum % (first) character; e.g. the sum of B's % B
					//   |
					//###CCCCCC...
					//01234   x       <---- indices for mainbuffer (server) and send/recieve-buffer (server AND client)

					unicodeNumSum := 0
					for b := 1 + i; b < opts.BufferSize; b++ {
						unicodeNumSum = int(unicodeNumSum) + int(bufs[i][b])
					}

					// idea: ( A+A+A+A+A+... % A ) + A = A, we want to track only one char per wave BUT it has to be dependant on every buffer position!
					mainbuf[1+i] = byte(unicodeNumSum%int(bufs[i][1+i])) + bufs[i][1+i]

				} else {
					// dropped/failed reads
					mainbuf[1+i] = bufs[i][1+i]
					countedDrops++

					// try to derive valid state from right / left neighbour
					if opts.UndoDrops {
						reconstructSuccess := false

						// Case: to the left (always applicable)
						if mainbuf[i] != byte('[') && mainbuf[i] != byte('_') {
							// increment the left neighbour
							mainbuf[1+i] = byte('A' + (mainbuf[i]-64)%26)
							reconstructSuccess = true
							countedCorrections++
						}

						if !opts.SimpleCorrection {
							// Case: to the right
							// first check: we must have a past iteration and the position to the right must be sensible
							if !reconstructSuccess && itrcounter > 0 && mainbuf[2+i] != byte(']') && mainbuf[2+i] != byte('_') {
								// move the right neighbour (from the past iteration!) to the left
								mainbuf[1+i] = mainbuf[2+i]
								reconstructSuccess = true
								countedCorrections++
							}
						}

						if reconstructSuccess {
							for b := 1 + i; b < opts.BufferSize; b++ {
								bufs[i][b] = mainbuf[1+i]
							}
						}

					}
				}

				// create valid prefix #, ##, ### etc. for every wave
				for b := 0; b < 1+i; b++ {
					bufs[i][b] = byte('#')
				}

				if opts.Reciprocity {

					startWrite = time.Now()
					n, err := conn.Write(bufs[i])
					deltaWrite = time.Since(startWrite)
					sentBytes = sentBytes + uint64(len(bufs[i]))
					if err != nil {
						log.Fatal(err)
					}
					if opts.Verbose {
						log.Println("<SERVER> Iteration:", itrcounter, " sent ", n, " bytes back to wave-buffer ", i, " - ", string(bufs[i])[:opts.BufferPrintSize])
					}

				}
				time.Sleep(time.Duration((halfIntervalTime * 1000000000 / float64(opts.NumWaves))) * time.Nanosecond)

			}

			printf("\n\n <SERVER> #%d Result: %s\n", itrcounter, string(mainbuf)[:opts.BufferPrintSize])
			time.Sleep(time.Duration(halfIntervalTime*1000000000) * time.Nanosecond)

			totalRead = totalRead + readBytes
			totalSent = totalSent + sentBytes
			totalDropped = totalDropped + countedDrops
			loopDelta = time.Since(startLoop)

			sentMbps = (float64(sentBytes*8) / 1000000) / loopDelta.Seconds()
			readMbps = (float64(readBytes*8) / 1000000) / loopDelta.Seconds()

			printf("\n          Iteration #%d took %fs:", itrcounter, loopDelta.Seconds())
			if opts.Acceleration {
				printf("\n          targeted run time for this iteration was %-4fs = max(%f, %f x %f)", halfIntervalTime*2, opts.MinInterval, opts.Interval, acclerationFactor)
			}
			printf("\n          %d Bytes were sent with approx. %-4f Mbps/iteration, %-4fs for the write call", sentBytes, sentMbps, deltaWrite.Seconds())
			printf("\n          %d Bytes were recieved with approx. %-4f Mbps/iteration with %-4fs for %d read attempts", readBytes, readMbps, deltaRead.Seconds(), totalReadAttempts)
			if opts.UndoDrops {
				printf("\n          %d counted drops with %d corrections (-u flag)", countedDrops, countedCorrections)
			}
			printf("\n          Current totals: %fs runtime, %d Bytes sent, %d Bytes read, %d transfers dropped\n\n\n\n", time.Since(startServer).Seconds(), totalSent, totalRead, totalDropped)

			if itrcounter >= opts.MaxIterations {
				printf("\n\n <SERVER> finished!\n\n          reason: %d iterations run, goal: %d\n\n          total time:%fs", itrcounter, opts.MaxIterations, time.Since(startServer).Seconds())
				// give to other host atleast one full interval to finish
				time.Sleep(time.Duration(halfIntervalTime*2) * time.Second)
				conn.Close()
				os.Exit(0)
			}
			if totalRead >= opts.Bytes {
				printf("\n\n <SERVER> finished!\n\n         reason: %d bytes recieved, goal: %d\n\n          total time:%fs", totalRead, opts.Bytes, time.Since(startServer).Seconds())
				// give to other host atleast one full interval to finish; not effective when '-r' was chosen (the other side always waits)
				time.Sleep(time.Duration(halfIntervalTime*2) * time.Second)
				conn.Close()
				os.Exit(0)
			}
		}

	} else {
		startClient := time.Now()

		switch opts.Profile {
		case taps.Scavenger.String():
			capacity = taps.Scavenger
		case taps.LowLatencyInteractive.String():
			capacity = taps.LowLatencyInteractive
		default:
			capacity = taps.Default
		}

		RemoteSpecifier := taps.RemoteEndpoint{}
		RemoteSpecifier.Address = opts.Client
		RemoteSpecifier.Protocol = proto

		Preconnection := taps.Preconnection{
			RemoteEndpoint: &RemoteSpecifier,
			ConnectionPreferences: &taps.ConnectionPreferences{
				ConnCapacityProfile: capacity,
			},
		}

		conn, err := Preconnection.Initiate()
		if err == nil {

			bufs := make(map[int][]byte)
			var totalRead, totalSent, totalDropped uint64 = 0, 0, 0

			for i := 0; i < opts.NumWaves; i++ {
				bufs[i] = make([]byte, opts.BufferSize)

				// fill with (literal) zeros
				for b := 0; b < opts.BufferSize; b++ {
					bufs[i][b] = byte('0')
				}
				// init with (effectivly) with A,B,C,... but with -1 (e.g. A as 64 rather than 65) because the main loop increments with 1
				bufs[i][1+i] = byte(64 + (i % 26))

			}

			for {
				startLoop = time.Now()
				var sentBytes, readBytes, countedDrops uint64
				var currentReadAttempts, currentReadBytesSum int
				var validState bool
				var sentMbps, readMbps, acclerationFactor float64
				halfIntervalTime, acclerationFactor = calcWaitTime(itrcounter)

				totalReadAttempts := 0
				countedDrops = 0
				itrcounter++
				for i := 0; i < opts.NumWaves; i++ {
					// every stream manages one particular character and its incrementation
					//01234   x       <---- indices for mainbuffer (server) and send/recieve-buffer (server AND client); the mainbuffer ends with ']' at index opts.NumWaves (x)
					//[ABCD...]       <---- example for the first timestep); [BCDE...] second timestep etc. (mainbuffer / server perspective)
					// |||
					//#AAAAAAAA...
					//  ||
					//##BBBBBBB...    <---- what the clients sent and is constructed in the loop below
					//   |
					//###CCCCCC...
					//01234   x       <---- indices for mainbuffer (server) and send/recieve-buffer (server AND client)

					// don't increment failed/dropped reads
					if bufs[i][1+i] != byte('_') {
						// the -64 is the incrementation, rather than 65 as baseline for capital A
						incrementedChar := byte('A' + ((bufs[i][1+i] - 64) % 26))
						for b := 1 + i; b < opts.BufferSize; b++ {
							bufs[i][b] = incrementedChar
						}
					} else {
						countedDrops++
					}

					// create valid prefix #, ##, ### etc. for every wave
					for b := 0; b < 1+i; b++ {
						bufs[i][b] = byte('#')
					}

					startWrite = time.Now()
					n, err := conn.Write(bufs[i])
					deltaWrite = time.Since(startWrite)
					sentBytes = sentBytes + uint64(len(bufs[i]))

					if err != nil {
						log.Fatal(err)
					}
					if opts.Verbose {
						log.Println("<CLIENT> Iteration:", itrcounter, " sent ", n, " bytes to server from wave-buffer ", i, " - ", string(bufs[i])[:opts.BufferPrintSize])
					}

					if opts.Reciprocity {

						startRead = time.Now()
						if opts.SimpleRead {
							currentReadAttempts, currentReadBytesSum, validState = readSimple(bufs, conn, i)
						} else {
							currentReadAttempts, currentReadBytesSum, validState = readAdvanced(bufs, conn, i, true)
						}
						deltaRead = time.Since(startRead)
						readBytes = readBytes + uint64(currentReadBytesSum)
						totalReadAttempts = totalReadAttempts + currentReadAttempts

						if opts.Verbose {
							if validState {
								log.Println("<CLIENT> Iteration:", itrcounter, " read ", currentReadBytesSum, " read bytes in ", currentReadAttempts, " read-attempts via wave ", i, " - ", string(bufs[i])[:opts.BufferPrintSize])
							} else {
								log.Println("<CLIENT> Iteration:", itrcounter, " dropped after ", currentReadBytesSum, " read bytes in ", currentReadAttempts, " read-attempts via wave ", i, " - ", string(bufs[i])[:opts.BufferPrintSize])
							}

						}

						// failed/dropped reads will be shown with underscores
						if !validState {
							for b := 1 + i; b < opts.BufferSize; b++ {
								bufs[i][b] = byte('_')
							}
						}

					}
					time.Sleep(time.Duration((halfIntervalTime * 1000000000 / float64(opts.NumWaves))) * time.Nanosecond)
				}

				if !opts.Verbose {
					printf("\n\n <CLIENT> Finished iteration #%d\n", itrcounter)
				}
				time.Sleep(time.Duration(halfIntervalTime*1000000000) * time.Nanosecond)

				totalRead = totalRead + readBytes
				totalSent = totalSent + sentBytes
				totalDropped = totalDropped + countedDrops
				loopDelta = time.Since(startLoop)

				sentMbps = (float64(sentBytes*8) / 1000000) / loopDelta.Seconds()
				readMbps = (float64(readBytes*8) / 1000000) / loopDelta.Seconds()
				printf("\n          Iteration #%d took %fs:", itrcounter, loopDelta.Seconds())
				if opts.Acceleration {
					printf("\n          targeted run time for this iteration was %-4fs = max(%f, %f x %f)", halfIntervalTime*2, opts.MinInterval, opts.Interval, acclerationFactor)
				}
				printf("\n          %d Bytes were sent with approx. %-4f Mbps/iteration, %-4fs for the write call", sentBytes, sentMbps, deltaWrite.Seconds())
				printf("\n          %d Bytes were recieved with approx. %-4f Mbps/iteration with %-4fs for %d read attempts", readBytes, readMbps, deltaRead.Seconds(), totalReadAttempts)
				if opts.UndoDrops {
					printf("\n          %d counted drops", countedDrops)
				}
				printf("\n          Current totals: %fs runtime, %d Bytes sent, %d Bytes read, %d transfers dropped\n\n\n\n", time.Since(startClient).Seconds(), totalSent, totalRead, totalDropped)

				if itrcounter >= opts.MaxIterations {
					printf("\n\n <CLIENT> finished!\n\n          reason: %d iterations run, goal: %d\n\n          total time:%fs", itrcounter, opts.MaxIterations, time.Since(startClient).Seconds())
					// give the other host atleast one full interval to finish
					time.Sleep(time.Duration(halfIntervalTime*2) * time.Second)
					conn.Close()
					os.Exit(0)
				}
				if totalSent >= opts.Bytes {
					printf("\n\n <CLIENT> finished!\n\n          reason: %d bytes sent, goal: %d\n\n          total time:%fs", totalSent, opts.Bytes, time.Since(startClient).Seconds())
					// give the other host atleast one full interval to finish; not effective when '-r' was chosen (the other side always waits)
					time.Sleep(time.Duration(halfIntervalTime*2) * time.Second)
					conn.Close()
					os.Exit(0)
				}
			}
		}
	}

}
