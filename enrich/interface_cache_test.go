package enrich

import "testing"

func TestInterfaceCacheUpdateLookup(t *testing.T) {
	cache := NewInterfaceCache()
	cache.Update("192.0.2.1", map[uint32]InterfaceMetadata{
		10: {Name: "Port1", Alias: "Uplink", SpeedBps: 1_000_000_000},
	})

	meta, ok := cache.Lookup("192.0.2.1", 10)
	if !ok {
		t.Fatalf("expected interface metadata")
	}
	if meta.Name != "Port1" {
		t.Fatalf("expected Name Port1, got %q", meta.Name)
	}
	if meta.Alias != "Uplink" {
		t.Fatalf("expected Alias Uplink, got %q", meta.Alias)
	}
	if meta.SpeedBps != 1_000_000_000 {
		t.Fatalf("expected SpeedBps 1_000_000_000, got %d", meta.SpeedBps)
	}
}
