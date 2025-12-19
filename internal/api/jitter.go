package api

import (
	"math/rand"
	"time"
)

// jitterInterval returns a duration randomly in [0.5x, 1.5x] of base to avoid thundering herd.
func jitterInterval(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	f := 0.5 + rand.Float64()
	return time.Duration(float64(base) * f)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
