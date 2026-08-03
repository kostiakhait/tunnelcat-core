// Copyright (c) 2026 Konstantin Khait

package core

import (
	"math/rand"
	"time"
)

const (
	// jitterBusyIRI: if the previous POST finished less than this ago, the
	// tunnel is under real-time load — apply zero jitter.
	jitterBusyIRI = 20 * time.Millisecond

	// jitterFullIRI: at or above this inter-request interval the tunnel is
	// lightly loaded — apply the full camouflage jitter.
	jitterFullIRI = 200 * time.Millisecond

	// jitterMax is the maximum random delay injected when the tunnel is idle.
	jitterMax = 40 * time.Millisecond
)

// adaptiveJitter returns a random sleep duration proportional to the
// inter-request interval (iri).  The scaling rule is:
//
//	iri < jitterBusyIRI    → 0         (real-time / high-load, don't interfere)
//	iri ∈ [busy, full)     → 0 … max  (linear scale — moderate load)
//	iri ≥ jitterFullIRI    → 0 … max  (full camouflage jitter)
//
// A zero iri (first request after start) is treated as jitterFullIRI so the
// very first POST gets a realistic random delay.
func adaptiveJitter(iri time.Duration, rng *rand.Rand) time.Duration {
	if iri == 0 {
		iri = jitterFullIRI
	}
	if iri < jitterBusyIRI {
		return 0
	}
	// Scale factor ∈ (0, 1].
	scale := float64(iri-jitterBusyIRI) / float64(jitterFullIRI-jitterBusyIRI)
	if scale > 1 {
		scale = 1
	}
	ceiling := time.Duration(float64(jitterMax) * scale)
	if ceiling <= 0 {
		return 0
	}
	return time.Duration(rng.Int63n(int64(ceiling)))
}
