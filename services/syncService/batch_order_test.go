package syncServices

import "testing"

// F-SYNC-01: a batch is a run of consecutive heights. Repeated or unordered
// indices let a block that failed verification reach the apply pass.
func TestBatchIndicesMustBeConsecutive(t *testing.T) {
	for _, ok := range [][]int64{{5}, {5, 6, 7}, {0, 1}} {
		if !batchIndicesConsecutive(ok) {
			t.Errorf("%v refused", ok)
		}
	}
	for _, bad := range [][]int64{{}, {5, 5}, {5, 6, 6}, {6, 5}, {5, 7}, {5, 6, 5}} {
		if batchIndicesConsecutive(bad) {
			t.Errorf("%v accepted", bad)
		}
	}
}
