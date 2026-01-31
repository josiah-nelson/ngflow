package enrich

import "sync"

type InterfaceCache struct {
	mu   sync.RWMutex
	data map[string]map[uint32]InterfaceMetadata
}

func NewInterfaceCache() *InterfaceCache {
	return &InterfaceCache{
		data: make(map[string]map[uint32]InterfaceMetadata),
	}
}

func (c *InterfaceCache) Update(exporter string, entries map[uint32]InterfaceMetadata) {
	if exporter == "" || len(entries) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.data[exporter]; !ok {
		c.data[exporter] = make(map[uint32]InterfaceMetadata)
	}

	for ifIndex, meta := range entries {
		c.data[exporter][ifIndex] = meta
	}
}

func (c *InterfaceCache) Lookup(exporter string, ifIndex uint32) (InterfaceMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ifaces, ok := c.data[exporter]
	if !ok {
		return InterfaceMetadata{}, false
	}
	meta, ok := ifaces[ifIndex]
	return meta, ok
}
