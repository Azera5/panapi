package quic

import (
	"context"
	"sync"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsys-lab/panapi/rpc"
	"github.com/netsys-lab/panapi/taps"
)

// Path-specific selector
type PinnedSelector struct {
	inner taps.Selector

	mu     sync.Mutex
	pinned *pan.Path
}

func NewPinnedSelector(inner taps.Selector) *PinnedSelector {
	return &PinnedSelector{inner: inner}
}

func (s *PinnedSelector) Initialize(local, remote pan.UDPAddr, paths []*pan.Path) {
	s.inner.Initialize(local, remote, paths)
}

func (s *PinnedSelector) SetPreferences(prefs *taps.ConnectionPreferences) error {
	return s.inner.SetPreferences(prefs)
}

func (s *PinnedSelector) Path(ctx context.Context) *pan.Path {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pinned != nil {
		return s.pinned
	}
	p := s.inner.Path(ctx)
	s.pinned = p
	return p
}

func (s *PinnedSelector) Refresh(paths []*pan.Path) {
	s.inner.Refresh(paths)
}

func (s *PinnedSelector) PathDown(fp pan.PathFingerprint, pi pan.PathInterface) {
	s.inner.PathDown(fp, pi)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pinned != nil && s.pinned.Fingerprint == fp {
		s.pinned = nil
	}
}

func (s *PinnedSelector) Close() error {
	if sc, ok := s.inner.(*rpc.SelectorClient); ok {
		return sc.NotifyClosed()
	}
	return s.inner.Close()
}

func (s *PinnedSelector) PinnedFingerprint() (pan.PathFingerprint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pinned == nil {
		return "", false
	}
	return s.pinned.Fingerprint, true
}