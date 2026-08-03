// Copyright (c) 2026 Konstantin Khait

package core

import (
	"testing"
	"time"
)

// seedFailRatio directly seeds td's rolling outcome window so FailRatio()
// reports approximately the given ratio, without waiting on real timers.
// total must be >= dialWinMinSamples and the window must span >= dialWinMinSpan.
func seedFailRatio(td *TunnelDialer, ratio float64, total int) {
	now := time.Now()
	fails := int(ratio * float64(total))
	td.dialWindow = make([]dialOutcome, 0, total)
	for i := 0; i < total; i++ {
		// Spread samples across a span comfortably over dialWinMinSpan so the
		// FailRatio guard doesn't zero them out.
		at := now.Add(-dialWinSize + time.Duration(i)*time.Millisecond)
		td.dialWindow = append(td.dialWindow, dialOutcome{at: at, success: i >= fails})
	}
}

func TestPickWeightHealthyDialerFullWeight(t *testing.T) {
	td := newTestDialer(t)
	got := pickWeight(td)
	want := 1.0 / float64(defaultPickRTT)
	if got != want {
		t.Errorf("healthy dialer: got weight %v, want %v (no RTT data, no failures)", got, want)
	}
}

func TestPickWeightScalesDownWithFailRatio(t *testing.T) {
	td := newTestDialer(t)
	seedFailRatio(td, 0.5, 20)

	got := pickWeight(td)
	base := 1.0 / float64(defaultPickRTT)
	want := base * 0.5
	if got != want {
		t.Errorf("50%% fail ratio: got weight %v, want %v", got, want)
	}
	if got >= base {
		t.Errorf("weight %v should be strictly less than the full-quality weight %v", got, base)
	}
}

func TestPickWeightFloorsAtSoftMinQuality(t *testing.T) {
	td := newTestDialer(t)
	seedFailRatio(td, 0.95, 20) // quality would be 0.05, below softMinQuality

	got := pickWeight(td)
	base := 1.0 / float64(defaultPickRTT)
	want := base * softMinQuality
	if got != want {
		t.Errorf("near-total fail ratio: got weight %v, want floor %v", got, want)
	}
	if got <= 0 {
		t.Errorf("weight must stay strictly positive (deprioritize, not exclude), got %v", got)
	}
}

// TestPickDeprioritizesWithoutExcluding is the end-to-end version of the "sick
// node stays in the pool but gets picked less" requirement: a struggling
// dialer (203.0.113.1-style — fine RTT, bad reliability) must be picked
// noticeably less often than a healthy sibling, but never literally zero.
func TestPickDeprioritizesWithoutExcluding(t *testing.T) {
	healthy := newTestDialer(t)
	sick := newTestDialer(t)
	seedFailRatio(sick, 0.6, 20) // above firstFailRatio(0.5) — would hard-evict via the
	// existing hook-based mechanism in real use; Pick() itself only sees the weight.

	pool := NewDialerPool([]*TunnelDialer{healthy, sick})

	const trials = 20000
	counts := map[*TunnelDialer]int{}
	for i := 0; i < trials; i++ {
		d := pool.Pick()
		if d == nil {
			t.Fatal("Pick returned nil")
		}
		counts[d]++
	}

	healthyCount, sickCount := counts[healthy], counts[sick]
	if sickCount == 0 {
		t.Error("sick dialer was never picked — should be deprioritized, not excluded")
	}
	if sickCount >= healthyCount {
		t.Errorf("sick dialer picked %d times, healthy only %d — expected sick to be picked less often", sickCount, healthyCount)
	}
	// With quality 0.4 vs 1.0, expect roughly a 1:2.5 ratio (~28.5%/71.5%); allow
	// a wide statistical margin since this is a random trial, just confirm the
	// skew is real and in the right direction rather than pinning exact counts.
	sickShare := float64(sickCount) / float64(trials)
	if sickShare > 0.40 {
		t.Errorf("sick dialer's pick share %.2f looks too high for a 0.6 fail ratio", sickShare)
	}
}
