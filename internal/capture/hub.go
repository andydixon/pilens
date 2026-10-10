package capture

import (
	"sync"
	"sync/atomic"
)

// Hub fans out live events to browser subscribers. A subscriber that cannot
// keep up loses events (counted) and is told to resync; capture never waits.
type Hub struct {
	mu   sync.Mutex
	subs map[*Sub]struct{}
}

type Event struct {
	Type string // SSE event name
	Data []byte // JSON
}

type Sub struct {
	C       chan Event
	Dropped atomic.Int64
	Resync  atomic.Bool
}

func NewHub() *Hub { return &Hub{subs: map[*Sub]struct{}{}} }

func (h *Hub) Subscribe() *Sub {
	s := &Sub{C: make(chan Event, 64)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

func (h *Hub) Unsubscribe(s *Sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		select {
		case s.C <- e:
		default:
			s.Dropped.Add(1)
			s.Resync.Store(true)
		}
	}
}

