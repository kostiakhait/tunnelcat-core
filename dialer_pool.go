// Copyright (c) 2026 Konstantin Khait

package core

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// dialerState is the lifecycle state of a slot in DialerPool.
type dialerState int8

const (
	// dialerStandby is a warm, authenticated dialer eligible for Pick().
	dialerStandby dialerState = iota
	// dialerDraining accepts no new connections; transitions back to dialerStandby
	// once OpenConns() drops to zero.
	dialerDraining
)

type dialerSlot struct {
	dialer *TunnelDialer
	state  dialerState
}

// DialerPool manages a set of TunnelDialers with RTT-weighted selection.
//
// Pick() selects from all non-draining dialers with probability proportional
// to 1/RTT, so faster controls receive more connections automatically.
// Dialers without sufficient RTT data yet receive a default weight equivalent
// to defaultPickRTT so new dialers participate until real measurements arrive.
// Draining dialers finish in-flight connections then return to standby.
type DialerPool struct {
	mu           sync.Mutex
	slots        []*dialerSlot
	evictCount   int32 // incremented by Evict; read+reset by DrainEvictions
	activityHook func()
}

// defaultPickRTT is the assumed RTT for dialers with no measured data yet.
const defaultPickRTT = time.Second

// softMinQuality floors the reliability multiplier applied in pickWeight so a
// struggling-but-not-yet-evicted dialer keeps some chance of being picked
// (useful when it's briefly the only in-country control available) rather
// than dropping to near-zero weight before the hard-eviction thresholds in
// recordDialOutcome (50%/80%) even get a chance to fire.
const softMinQuality = 0.1

// NewDialerPool creates a pool from the given dialers (all start as standby).
func NewDialerPool(dialers []*TunnelDialer) *DialerPool {
	p := &DialerPool{}
	for _, d := range dialers {
		p.slots = append(p.slots, &dialerSlot{dialer: d, state: dialerStandby})
	}
	return p
}

// SetActivityHook registers fn to be called on every tunnel POST by any dialer.
func (p *DialerPool) SetActivityHook(fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.activityHook = fn
	for _, s := range p.slots {
		s.dialer.SetActivityHook(fn)
	}
}

// Pick selects a dialer with probability proportional to 1/RTT.
// Returns nil only when every slot is draining or the pool is empty.
func (p *DialerPool) Pick() *TunnelDialer {
	p.mu.Lock()
	defer p.mu.Unlock()

	var total float64
	for _, s := range p.slots {
		if s.state != dialerDraining {
			total += pickWeight(s.dialer)
		}
	}
	if total == 0 {
		return nil
	}

	r := rand.Float64() * total
	for _, s := range p.slots {
		if s.state == dialerDraining {
			continue
		}
		r -= pickWeight(s.dialer)
		if r <= 0 {
			return s.dialer
		}
	}
	// Floating-point residual: return last non-draining dialer.
	for i := len(p.slots) - 1; i >= 0; i-- {
		if p.slots[i].state != dialerDraining {
			return p.slots[i].dialer
		}
	}
	return nil
}

// pickWeight returns 1/RTT for a dialer (or 1/defaultPickRTT if no data yet),
// scaled down by its current failure ratio so a control that's reliably fast
// but increasingly unreliable gets deprioritized smoothly — rather than
// keeping full weight right up until it either recovers or crosses the hard
// eviction threshold. Recomputed fresh on every call from the live window
// (TunnelDialer.FailRatio), so it self-heals as soon as reliability improves,
// no separate recovery state needed.
func pickWeight(td *TunnelDialer) float64 {
	rtt := td.TrafficRTT()
	if rtt <= 0 {
		rtt = defaultPickRTT
	}
	base := 1.0 / float64(rtt)
	quality := 1.0 - td.FailRatio()
	if quality < softMinQuality {
		quality = softMinQuality
	}
	return base * quality
}

// PickForUID returns a dialer (ignores UID — exit stickiness handled by control).
func (p *DialerPool) PickForUID(_ int) *TunnelDialer {
	return p.Pick()
}

// Size returns the number of non-draining dialers.
func (p *DialerPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sizeUnlocked()
}

// LastDataTime returns the most recent successful POST time across all dialers.
func (p *DialerPool) LastDataTime() time.Time {
	p.mu.Lock()
	slots := make([]*dialerSlot, len(p.slots))
	copy(slots, p.slots)
	p.mu.Unlock()
	var latest time.Time
	for _, s := range slots {
		if t := s.dialer.LastDataTime(); t.After(latest) {
			latest = t
		}
	}
	return latest
}

// Add appends td as a standby dialer eligible for Pick().
func (p *DialerPool) Add(td *TunnelDialer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.activityHook != nil {
		td.SetActivityHook(p.activityHook)
	}
	p.slots = append(p.slots, &dialerSlot{dialer: td, state: dialerStandby})
	Log.Printf("dialer-pool: added dialer addr=%s pool=%d", td.ServerURL(), len(p.slots))
}

// Evict removes td from the pool.
func (p *DialerPool) Evict(td *TunnelDialer) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	found := false
	next := p.slots[:0]
	for _, s := range p.slots {
		if s.dialer == td {
			found = true
		} else {
			next = append(next, s)
		}
	}
	if !found {
		return p.sizeUnlocked()
	}
	p.slots = next
	atomic.AddInt32(&p.evictCount, 1)
	n := p.sizeUnlocked()
	Log.Printf("dialer-pool: evicted addr=%s %d remaining", td.ServerURL(), n)
	return n
}

// Swap replaces all dialers wholesale.
func (p *DialerPool) Swap(dialers []*TunnelDialer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.activityHook != nil {
		for _, d := range dialers {
			d.SetActivityHook(p.activityHook)
		}
	}
	p.slots = p.slots[:0]
	for _, d := range dialers {
		p.slots = append(p.slots, &dialerSlot{dialer: d, state: dialerStandby})
	}
	Log.Printf("dialer-pool: swapped to %d dialer(s)", len(dialers))
}

// NeedsRefill reports whether the pool has fewer than target non-draining dialers.
func (p *DialerPool) NeedsRefill(target int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sizeUnlocked() < target
}

// Has reports whether the pool already contains a non-draining dialer for ctrlURL.
func (p *DialerPool) Has(ctrlURL string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.slots {
		if s.state != dialerDraining && s.dialer.ServerURL() == ctrlURL {
			return true
		}
	}
	return false
}

// Get returns the non-draining dialer for ctrlURL, or nil if not present.
func (p *DialerPool) Get(ctrlURL string) *TunnelDialer {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.slots {
		if s.state != dialerDraining && s.dialer.ServerURL() == ctrlURL {
			return s.dialer
		}
	}
	return nil
}

// DrainEvictions returns and resets the eviction counter.
func (p *DialerPool) DrainEvictions() int {
	return int(atomic.SwapInt32(&p.evictCount, 0))
}

// StartManagement launches the drain-completion background loop.
func (p *DialerPool) StartManagement(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
				p.manage()
			}
		}
	}()
}

// manage runs one tick: drain completion.
func (p *DialerPool) manage() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.slots {
		if s.state == dialerDraining && s.dialer.OpenConns() == 0 {
			s.state = dialerStandby
			Log.Printf("dialer-pool: drained → standby addr=%s", s.dialer.ServerURL())
		}
	}
}

func (p *DialerPool) sizeUnlocked() int {
	n := 0
	for _, s := range p.slots {
		if s.state != dialerDraining {
			n++
		}
	}
	return n
}

func dialerStateName(s dialerState) string {
	switch s {
	case dialerDraining:
		return "draining"
	default:
		return "standby"
	}
}
