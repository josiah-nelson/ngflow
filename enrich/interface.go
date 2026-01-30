package enrich

import "net"

type InterfaceMetadata struct {
	Name     string
	Alias    string
	SpeedBps uint64
}

type InterfaceFetcher interface {
	Fetch(target string) (map[uint32]InterfaceMetadata, error)
}

type InterfaceEnricher interface {
	Lookup(exporterIP net.IP, ifIndex uint32) (InterfaceMetadata, bool)
	ObserveExporter(exporterIP net.IP)
}
