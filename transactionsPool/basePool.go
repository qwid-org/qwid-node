package transactionsPool

type PriorityQueue []*Item

func (pq PriorityQueue) Len() int { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool {
	return pq[i].priority > pq[j].priority
}
func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}
func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*Item)
	item.index = n
	*pq = append(*pq, item)
}
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// minQueue orders the same Items cheapest-first (S4-08), so a full pool finds
// its eviction candidate in O(log n) instead of scanning every entry - with
// 50 000 pooled, one gossip message of 5 000 transactions used to cost ~250M
// comparisons under the pool's write lock.
type minQueue []*Item

func (q minQueue) Len() int           { return len(q) }
func (q minQueue) Less(i, j int) bool { return q[i].priority < q[j].priority }
func (q minQueue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].minIndex = i
	q[j].minIndex = j
}
func (q *minQueue) Push(x interface{}) {
	item := x.(*Item)
	item.minIndex = len(*q)
	*q = append(*q, item)
}
func (q *minQueue) Pop() interface{} {
	old := *q
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.minIndex = -1
	*q = old[:n-1]
	return item
}
