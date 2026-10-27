package server

import "time"

// SetStatePersistInterval changes how often a running attack saves state.json
// and returns a function restoring the previous interval.
func SetStatePersistInterval(d time.Duration) func() {
	previous := statePersistInterval
	statePersistInterval = d
	return func() { statePersistInterval = previous }
}
