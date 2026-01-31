package enrich

import (
	"net"
	"testing"
)

type fakeFetcher struct {
	called int
}

func (f *fakeFetcher) Fetch(target string) (map[uint32]InterfaceMetadata, error) {
	f.called++
	return map[uint32]InterfaceMetadata{
		5: {Name: "Port5", Alias: "Edge", SpeedBps: 100_000_000},
	}, nil
}

func TestSNMPPollerUpdatesCache(t *testing.T) {
	cache := NewInterfaceCache()
	fetcher := &fakeFetcher{}
	poller := NewSNMPPoller(cache, fetcher, 1)
	poller.ObserveExporter(parseIP("192.0.2.9"))
	poller.pollDue()

	if fetcher.called != 1 {
		t.Fatalf("expected fetcher called once, got %d", fetcher.called)
	}
	meta, ok := cache.Lookup("192.0.2.9", 5)
	if !ok {
		t.Fatalf("expected interface metadata in cache")
	}
	if meta.Name != "Port5" {
		t.Fatalf("expected Port5, got %q", meta.Name)
	}
}

func parseIP(ip string) net.IP {
	return net.ParseIP(ip)
}
