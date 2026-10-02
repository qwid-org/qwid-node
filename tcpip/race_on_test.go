//go:build race

package tcpip

// raceEnabled: the race detector makes sync.Pool drop items at random, so
// allocation measurements are meaningless under -race.
const raceEnabled = true
