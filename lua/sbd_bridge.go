package lua

import (
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsys-lab/panapi/rpc"
	"github.com/netsys-lab/panapi/sbd"
	"github.com/quic-go/quic-go/logging"
	lua "github.com/yuin/gopher-lua"
)

// Interval at which path metrics are flushed to the observer
var sbdFlushInterval = 1 * time.Second

// Counts lost and acknowledged packets collected by the stats wrapper
type tickSample struct {
	lost, acked uint32
}

type pathMetric struct {
	pathID     pan.PathFingerprint
	interfaces []sbd.InterfaceID

	currentSample tickSample
	lastSample    tickSample

	totalLost uint32
	throughput float64 // latest estimate
}

// Finalizes the current sample as last and starts a new one
func (c *pathMetric) updateTickSample() tickSample {
	c.currentSample, c.lastSample = tickSample{}, c.currentSample
	return c.lastSample
}

// Connects QUIC stats and path selection to the sbd.SBDAnalyser and exposes bottleneck and connection information to Lua
type SBDBridge struct {
	analyser *sbd.SBDAnalyser
	state    *State

	luaSelector *LuaSelector

	mu       sync.Mutex
	pathMetrics map[string]*pathMetric
}

func NewSBDBridge(state *State, cfg sbd.Config) *SBDBridge {
	b := &SBDBridge{
		analyser: sbd.NewSBDAnalyser(cfg),
		state:    state,
		pathMetrics: make(map[string]*pathMetric),
	}
	b.registerLuaFunctions()
	go b.flushLoop()
	return b
}

func (b *SBDBridge) registerLuaFunctions() {
	b.state.Lock()
	defer b.state.Unlock()

	mod, ok := b.state.RegisterModule("panapi", nil).(*lua.LTable)
	if !ok {
		b.state.Println("sbd: could not find the panapi Lua module")
		return
	}
	mod.RawSetString("BottleneckInterfaces", b.state.NewFunction(b.luaBottleneckInterfaces))
	mod.RawSetString("FilterBottlenecked", b.state.NewFunction(b.luaFilterBottlenecked))
	mod.RawSetString("ConnectionInfo", b.state.NewFunction(b.luaConnectionInfo))
}

func (b *SBDBridge) luaBottleneckInterfaces(L *lua.LState) int {
	L.Push(interfacesToLuaTable(L, b.analyser.BottleneckInterfaces()))
	return 1
}

// Provides path specific metrics to the lua script
func (b *SBDBridge) luaConnectionInfo(L *lua.LState) int {
	laddr := L.CheckString(1)
	raddr := L.CheckString(2)

	info, ok := b.ConnectionInfo(laddr, raddr)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	t := L.NewTable()
	t.RawSetString("PathID", lua.LString(info.PathID))
	t.RawSetString("Interfaces", interfacesToLuaTable(L, info.Interfaces))
	t.RawSetString("PacketLoss", lua.LNumber(info.PacketLoss))
	t.RawSetString("TotalLost", lua.LNumber(info.TotalLost))
	t.RawSetString("Throughput", lua.LNumber(info.Throughput))
	L.Push(t)
	return 1
}

// Stats wrapper that records packet loss, acknowledgments, and throughput for each pinned path
func (b *SBDBridge) WrapStats(inner rpc.ServerConnectionTracer) rpc.ServerConnectionTracer {
	return &sbdStatsWrapper{
		ServerConnectionTracer: inner, 
		bridge: b}
}

type sbdStatsWrapper struct {
	rpc.ServerConnectionTracer
	bridge *SBDBridge
}

func (w *sbdStatsWrapper) LostPacket(local, remote *pan.UDPAddr, level logging.EncryptionLevel, num logging.PacketNumber, reason logging.PacketLossReason) error {
	w.bridge.recordLoss(local, remote)
	return w.ServerConnectionTracer.LostPacket(local, remote, level, num, reason)
}

func (w *sbdStatsWrapper) AcknowledgedPacket(local, remote *pan.UDPAddr, level logging.EncryptionLevel, num logging.PacketNumber) error {
	w.bridge.recordAck(local, remote)
	return w.ServerConnectionTracer.AcknowledgedPacket(local, remote, level, num)
}

func (w *sbdStatsWrapper) UpdatedMetrics(local, remote *pan.UDPAddr, rttStats *rpc.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) error {
	if rttStats != nil {
		w.bridge.recordThroughput(local, remote, estimateThroughput(bytesInFlight, rttStats.SmoothedRTT))
	}
	return w.ServerConnectionTracer.UpdatedMetrics(local, remote, rttStats, cwnd, bytesInFlight, packetsInFlight)
}

func (w *sbdStatsWrapper) Close(local, remote *pan.UDPAddr) error {
	err := w.ServerConnectionTracer.Close(local, remote)
	w.bridge.forget(getConnKey(*local, *remote))
	return err
}

// Wraps the inner selector to track a pinned path
func (b *SBDBridge) WrapSelector(inner rpc.ServerSelector) rpc.ServerSelector {
	if ls, ok := inner.(*LuaSelector); ok {
		b.luaSelector = ls
	}
	return &sbdSelectorWrapper{
		ServerSelector: inner, 
		bridge: b}
}

type sbdSelectorWrapper struct {
	rpc.ServerSelector
	bridge *SBDBridge
}

func (w *sbdSelectorWrapper) Path(local, remote pan.UDPAddr) (*pan.Path, error) {
	path, err := w.ServerSelector.Path(local, remote)
	if err == nil && path != nil {
		w.bridge.registerPath(local, remote, path)
	}
	return path, err
}

func (w *sbdSelectorWrapper) Close(local, remote pan.UDPAddr) error {
	err := w.ServerSelector.Close(local, remote)
	w.bridge.forget(getConnKey(local, remote))
	return err
}

// Returns the map key for the pathMetrics entry of a pinnend connection
// each pinnend connection has its own local AddrPort, so its key is unique
func getConnKey(local, remote pan.UDPAddr) string {
	return local.String() + "|" + remote.String()
}

type ConnectionSnapshot struct {
	PathID     string
	Interfaces []sbd.InterfaceID
	PacketLoss float64 // percentage
	TotalLost  uint32
	Throughput float64
}

func (b *SBDBridge) ConnectionInfo(local, remote string) (info ConnectionSnapshot, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	connKey := local + "|" + remote
	c, found := b.pathMetrics[connKey]
	if !found || c.pathID == "" {
		return ConnectionSnapshot{}, false
	}
	return ConnectionSnapshot{
		PathID:     string(c.pathID),
		Interfaces: c.interfaces,
		PacketLoss: lossPercent(c.lastSample.lost, c.lastSample.acked),
		TotalLost:  c.totalLost,
		Throughput: c.throughput,
	}, true
}


func (b *SBDBridge) getPathMetrics(key string) *pathMetric {
	c, ok := b.pathMetrics[key]
	if !ok {
		c = &pathMetric{}
		b.pathMetrics[key] = c
	}
	return c
}

// Records the interfaces used by a connection's pinned path
func (b *SBDBridge) registerPath(local, remote pan.UDPAddr, path *pan.Path) {
	b.mu.Lock()
	defer b.mu.Unlock()

	c := b.getPathMetrics(getConnKey(local, remote))
	c.pathID = path.Fingerprint
	c.interfaces = toInterfaceIDs(path)
}

func (b *SBDBridge) recordLoss(local, remote *pan.UDPAddr) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.getPathMetrics(getConnKey(*local, *remote))
	c.currentSample.lost++
	c.totalLost++
}

func (b *SBDBridge) recordAck(local, remote *pan.UDPAddr) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.getPathMetrics(getConnKey(*local, *remote)).currentSample.acked++
}

func (b *SBDBridge) recordThroughput(local, remote *pan.UDPAddr, throughput float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.getPathMetrics(getConnKey(*local, *remote)).throughput = throughput
}

// Drops all state for a closed connection
func (b *SBDBridge) forget(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pathMetrics, key)
}

// Calls flushOnce every sbdFlushInterval until the process exits
func (b *SBDBridge) flushLoop() {
	ticker := time.NewTicker(sbdFlushInterval)
	defer ticker.Stop()
	for range ticker.C {
		b.flushOnce()
	}
}

// Finalises and forwards path metrics to the analyser if there was at least one packet loss
func (b *SBDBridge) flushOnce() {
	b.mu.Lock()
	var observations []sbd.PathObservation
	for _, c := range b.pathMetrics {
		justFlushed := c.updateTickSample()
		if justFlushed.lost == 0 || c.pathID == "" {
			continue
		}
		observations = append(observations, sbd.PathObservation{
			PathID:          c.pathID,
			PathInterfaces:  c.interfaces,
			PacketLossTotal: justFlushed.lost,
			PacketLossPct:   lossPercent(justFlushed.lost, justFlushed.acked),
			Throughput:    	 c.throughput,
			At:              time.Now(),
		})
	}
	b.mu.Unlock()

	// Runs outside b.mu: Observe locks the analyser itself
	for _, obs := range observations {
		b.analyser.Observe(obs)
	}
}

func lossPercent(lost, acked uint32) float64 {
	if total := lost + acked; total > 0 {
		return float64(lost) * 100 / float64(total)
	}
	return 0
}

func interfacesToLuaTable(L *lua.LState, ids []sbd.InterfaceID) *lua.LTable {
	t := L.NewTable()
	for _, id := range ids {
		t.Append(newLuaPathInterface(pan.PathInterface{IA: pan.IA(id.IA), IfID: pan.IfID(id.IfID)}))
	}
	return t
}

// Converts a path's interfaces to the sbd representation
func toInterfaceIDs(path *pan.Path) []sbd.InterfaceID {
	if path == nil || path.Metadata == nil {
		return nil
	}
	ids := make([]sbd.InterfaceID, len(path.Metadata.Interfaces))
	for i, pi := range path.Metadata.Interfaces {
		ids[i] = sbd.InterfaceID{IA: uint64(pi.IA), IfID: uint64(pi.IfID)}
	}
	return ids
}

// Estimates throughput as bytesInFlight / SmoothedRTT
func estimateThroughput(bytesInFlight logging.ByteCount, smoothedRTT time.Duration) float64 {
	if smoothedRTT <= 0 {
		return 0
	}
	bytesPerSecond := float64(bytesInFlight) / smoothedRTT.Seconds()
	if bytesPerSecond < 0 {
		return 0
	}
	return bytesPerSecond
}


// Filters paths into clean and affected based on whether they contain bottleneck interfaces
func (b *SBDBridge) luaFilterBottlenecked(L *lua.LState) int {
	argument := L.CheckTable(1)
	bottleneck := b.analyser.BottleneckInterfaces()

	clean := L.NewTable()
	affected := L.NewTable()

	argument.ForEach(func(_, v lua.LValue) {
		lt, ok := v.(*lua.LTable)
		if !ok {
			return
		}
		path := b.lookupPath(lt)
		if path == nil {
			clean.Append(lt)
			return
		}
		_, isAffected := sbd.FilterPathsByBottleneck([][]sbd.InterfaceID{toInterfaceIDs(path)}, bottleneck)
		if len(isAffected) > 0 {
			affected.Append(lt)
		} else {
			clean.Append(lt)
		}
	})

	L.Push(clean)
	L.Push(affected)
	return 2
}

// Helper for luaFilterBottlenecked, looks up the pan.Path represented by the given Lua table
func (b *SBDBridge) lookupPath(lt *lua.LTable) *pan.Path {
	if b.luaSelector == nil {
		return nil
	}
	return b.luaSelector.get_pan_path(lt)
}