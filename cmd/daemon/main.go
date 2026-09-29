// Copyright 2021 Thorben Krüger (thorben.krueger@ovgu.de)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"runtime/pprof"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsys-lab/panapi/lua"
	"github.com/netsys-lab/panapi/rpc"
	"github.com/netsys-lab/panapi/sbd"
	"github.com/netsys-lab/panapi/taps"
	"github.com/quic-go/quic-go/logging"
)

func main() {
	var (
		script   string
		cpulog   string
		selector rpc.ServerSelector
		err      error

		sbdLossEpsilon    float64
		sbdMinLoss        float64
		sbdThroughputPct  float64
		sbdWindowSize     int
		sbdClearanceDelay time.Duration
	)

	flag.StringVar(&script, "script", "", "Lua script for path selection")
	flag.StringVar(&cpulog, "cpulog", "", "Write profiling information to file")

	// Shared Bottleneck Detection (SBD)
	flag.Float64Var(&sbdLossEpsilon, "sbd-loss-epsilon", 15, "SBD: max absolute loss difference (%) for similarity")
	flag.Float64Var(&sbdMinLoss, "sbd-min-loss", 2, "SBD: minimum loss (%) before a path is considered degraded")
	flag.Float64Var(&sbdThroughputPct, "sbd-throughput-pct", 20, "SBD: max relative throughput difference (%) for similarity")
	flag.IntVar(&sbdWindowSize, "sbd-window-size", 8, "SBD: number of recent observations to buffer across all paths")
	flag.DurationVar(&sbdClearanceDelay, "sbd-clearance-delay", 2*time.Second, "SBD: delay before removing a cleared bottleneck")
	flag.Parse()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, os.Kill, os.Interrupt)

	l, err := net.ListenUnix("unix", rpc.DefaultDaemonAddress)
	if err != nil {
		log.Fatalf("Could not start daemon: %s", err)
	}
	log.Println("Starting daemon")

	// remove the underlying socket file on close
	l.SetUnlinkOnClose(true)

	if cpulog != "" {
		f, err := os.Create(cpulog)
		if err != nil {
			log.Fatal("cpuprofile:", err)
		}
		if err = pprof.StartCPUProfile(f); err != nil {
			log.Fatal("cpuprofile:", err)
		}
	}

	lua_state := lua.NewState()
	selector = lua.NewSelector(lua_state)
	stats := lua.NewStats(lua_state)

	// NewSBDBridge has to run after NewSelector: it adds its functions to the existing "panapi" module created by NewSelector
	sbdBridge := lua.NewSBDBridge(lua_state, sbd.Config{
		LossEpsilon:    sbdLossEpsilon,
		MinLoss:        sbdMinLoss,
		ThroughputPct:  sbdThroughputPct,
		WindowSize:     sbdWindowSize,
		ClearanceDelay: sbdClearanceDelay,
	})

	err = lua_state.LoadScript(script)
	if err != nil {
		log.Printf("Could not load path-selection script: %s", err)
		log.Println("Falling back to default selector")
		selector = rpc.NewServerSelectorFunc(func(pan.UDPAddr, pan.UDPAddr) taps.Selector {
			return &taps.DefaultSelector{}
		})
	}

	stats = sbdBridge.WrapStats(stats)
	selector = sbdBridge.WrapSelector(selector)

	server, err := rpc.NewServer(selector, logging.Tracer{}, stats)
	if err != nil {
		log.Fatalln(err)
	}

	go func() {
		log.Println("Started listening for rpc calls")
		server.Accept(l)
	}()
	sig := <-c
	log.Printf("Got signal [%s]: running defered cleanup and exiting.", sig)
	err = l.Close()
	if err != nil {
		log.Println(err)
	}
	//should be NOP if profiler is not running
	pprof.StopCPUProfile()
	os.Exit(0)
}
