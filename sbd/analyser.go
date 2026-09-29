package sbd

import (
	"fmt"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)


// pan.PathInterface encodes Isolation Domain *and* Autonomous System within the IA uint64 (16/ISD+48/AS bits),
// we mirror this approach for compatibility reasons
type InterfaceID struct {
	IA   uint64
	IfID uint64
}

// recently measured metrics for a single path
type PathObservation struct {

	PathID pan.PathFingerprint
	PathInterfaces []InterfaceID

	// metrics are relative to a window
	PacketLossTotal uint32
	PacketLossPct float64
	Throughput float64

	// moment of observation
	At time.Time
}

// tuning constants
type Config struct {

	// mirrors the drop of the oldest event if "len(sr.events)>8" from umcc/scheduler_sbd.go, 
	// but is directly configurable in this case, corresponds to the --sbd-window-size daemon flag
	WindowSize int

	// defines what similar loss actually is: path-loss-delta < or = LossEpsilon implies similarity,
	// corresponds to lossEpsilon in "umcc/scheduler_sbd.go" and the --sbd-loss-epsilon daemon flag
	LossEpsilon float64
	// corresponds to minLossToCompare in "umcc/scheduler_sbd.go" and the --sbd-min-loss daemon flag
	MinLoss float64

	// same idea as with LossEpsilon: path-tp-delta < or = ThroughputPct implies similarity,
	// corresponds to throughputPct in "umcc/scheduler_sbd.go" and the --sbd-throughput-pct daemon flag
	ThroughputPct float64
	// "umcc/scheduler_sbd.go" does not define the MinThroughput directly and assumes it to be 0, so do we

	// how long an interface keeps being reported by BottleneckInterfaces,
	// corresponds to the --sbd-clearance-delay daemon flag
	ClearanceDelay time.Duration
}
func (cfg Config) withDefaults() Config {
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 8
	}
	if cfg.LossEpsilon == 0 {
		cfg.LossEpsilon = 15
	}
	if cfg.MinLoss == 0 {
		cfg.MinLoss = 5
	}
	if cfg.ThroughputPct == 0 {
		cfg.ThroughputPct = 20
	}
	if cfg.ClearanceDelay <= 0 {
		cfg.ClearanceDelay = 2 * time.Second
	}
	return cfg
}

// implements sbd across the paths of one or more connections, 
// based on a sliding window of recent PathObservations
type SBDAnalyser struct {
	cfg Config

	mu           sync.Mutex
	window       []PathObservation
	lastDetected map[InterfaceID]time.Time
}
func NewSBDAnalyser(cfg Config) *SBDAnalyser {
	return &SBDAnalyser{
		cfg:          cfg.withDefaults(),
		lastDetected: make(map[InterfaceID]time.Time),
	}
}


// *** API ***

// port of "OnCongestionEvent" method in "umcc/scheduler_sbd.go"
func (a *SBDAnalyser) Observe(obs PathObservation) []InterfaceID {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.window = append(a.window, obs)
	if len(a.window) > a.cfg.WindowSize {
		a.window = a.window[1:]
	}

	affected := make(map[pan.PathFingerprint]bool)
	for i := 0; i < len(a.window); i++ {
		for j := i + 1; j < len(a.window); j++ {
			x, y := a.window[i], a.window[j]
			if x.PathID == y.PathID {
				continue
			}

			lossSimilar := x.PacketLossPct >= a.cfg.MinLoss &&
				y.PacketLossPct >= a.cfg.MinLoss &&
				isInEpsilonRange(x.PacketLossPct, y.PacketLossPct, a.cfg.LossEpsilon)

			throughputSimilar := x.Throughput > 0 && y.Throughput > 0 &&
				isWithinRelativePercent(float64(x.Throughput), float64(y.Throughput), a.cfg.ThroughputPct)

			if lossSimilar || throughputSimilar {
				// #todo: the bool itself is no longer relevant for currentPathsLocked
				affected[x.PathID] = true
				affected[y.PathID] = true
			}
		}
	}

	if len(affected) == 0 {
		return a.bottleneckInterfacesLocked()
	}

	// we know the suspicious paths by pan.PathFingerprint only,
	// but we need unique identifiers per interface rather than path
	paths, affectedIdx := a.currentPathsLocked(affected)

	if len(affectedIdx) >= len(paths) {
		return a.bottleneckInterfacesLocked()
	}

	bottleneck := FindSharedBottleneck(paths, affectedIdx)
	a.refreshDetectedLocked(bottleneck)

	return a.bottleneckInterfacesLocked()
}

func (a *SBDAnalyser) BottleneckInterfaces() []InterfaceID {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bottleneckInterfacesLocked()
}


// *** Helper ***

// preparation for the sbd-alg, a.mu must already be held
func (a *SBDAnalyser) currentPathsLocked(affected map[pan.PathFingerprint]bool) (paths [][]InterfaceID, affectedIdx []int) {
	
	index := make(map[pan.PathFingerprint]int, len(a.window))
	
	// first part: building paths <=> converting unique path identification to unique interface identification
	for _, obs := range a.window {
		// IF we've already seen this path, we *overwrite* the older interface details with the newer ones...
		if idx, ok := index[obs.PathID]; ok {
			paths[idx] = obs.PathInterfaces
			continue
		}
		// ...otherwise we simply append
		index[obs.PathID] = len(paths) 
		paths = append(paths, obs.PathInterfaces) 
	}
	
	// second part: building affectedIndx <=> converting the suspicious path list to relevant indicies regarding paths from the first part
	for pathID := range affected {
		if idx, ok := index[pathID]; ok {
			affectedIdx = append(affectedIdx, idx)
		}
	}
	
	return paths, affectedIdx
}

// refreshes the clearance timer, a.mu must already be held
func (a *SBDAnalyser) refreshDetectedLocked(bottleneck []InterfaceID) {
	now := time.Now()
	for _, iface := range bottleneck {
		a.lastDetected[iface] = now
	}
}

// returns every interface whose clearance delay has not yet elapsed, a.mu must already be held
func (a *SBDAnalyser) bottleneckInterfacesLocked() []InterfaceID {
	now := time.Now()
	var out []InterfaceID
	for iface, last := range a.lastDetected {
		fmt.Println(iface.IfID)
		// drop the interface if the detection is to old
		if now.Sub(last) > a.cfg.ClearanceDelay {
			delete(a.lastDetected, iface)
			continue
		}
		fmt.Println(iface.IfID)
		out = append(out, iface)
	}
	return out
}

// port of "isInEpsilonRange" function in "umcc/scheduler_sbd.go"
func isInEpsilonRange(x, y, epsilon float64) bool {
	if x > y {
		return x-y <= epsilon
	}
	return y-x <= epsilon
}

// port of "isWithinRelativePercent" function in "umcc/scheduler_sbd.go"
func isWithinRelativePercent(a, b, pct float64) bool {
	if a == 0 && b == 0 {
		return true
	}
	larger := a
	if b > larger {
		larger = b
	}
	var diff float64
	if a > b {
		diff = a - b
	} else {
		diff = b - a
	}
	return diff*100/larger <= pct
}


