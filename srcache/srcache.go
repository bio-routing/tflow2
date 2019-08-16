package srcache

import (
	"sync"

	"github.com/bio-routing/tflow2/config"

	bnet "github.com/bio-routing/bio-rd/net"
)

// SamplerateCache caches information about samplerates
type SamplerateCache struct {
	cache map[bnet.IP]uint64
	mu    sync.RWMutex
}

// New creates a new SamplerateCache and initializes it with values from the config
func New(agents []config.Agent) *SamplerateCache {
	c := &SamplerateCache{
		cache: make(map[bnet.IP]uint64),
	}

	// Initialize cache with configured samplerates
	for _, a := range agents {
		addr, err := bnet.IPFromString(a.IPAddress)
		if err != nil {
			// FIXME: Handle error
			continue
		}
		c.Set(addr, a.SampleRate)
	}

	return c
}

// Set updates a cache entry
func (s *SamplerateCache) Set(rtr bnet.IP, rate uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache[rtr] = rate
}

// Get gets a cache entry
func (s *SamplerateCache) Get(rtr bnet.IP) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.cache[rtr]; !ok {
		return 1
	}

	return s.cache[rtr]
}
