package enrich

import "net"

type InterfaceEnrichment struct {
	cache  *InterfaceCache
	poller *SNMPPoller
}

func NewInterfaceEnrichment(cache *InterfaceCache, poller *SNMPPoller) *InterfaceEnrichment {
	return &InterfaceEnrichment{
		cache:  cache,
		poller: poller,
	}
}

func (e *InterfaceEnrichment) Lookup(exporterIP net.IP, ifIndex uint32) (InterfaceMetadata, bool) {
	if e == nil || e.cache == nil || exporterIP == nil {
		return InterfaceMetadata{}, false
	}
	return e.cache.Lookup(exporterIP.String(), ifIndex)
}

func (e *InterfaceEnrichment) ObserveExporter(exporterIP net.IP) {
	if e == nil || e.poller == nil {
		return
	}
	e.poller.ObserveExporter(exporterIP)
}
