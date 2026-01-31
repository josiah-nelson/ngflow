package formatter

import (
	"encoding/json"
	"net"
	"strconv"
	"testing"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	pb "github.com/netsampler/goflow2/v2/pb"
	"github.com/josiah-nelson/ngflow/enrich"
	"github.com/josiah-nelson/ngflow/proto"
)

type fakeInterfaceEnricher struct {
	metadata map[string]map[uint32]enrich.InterfaceMetadata
}

func (f *fakeInterfaceEnricher) Lookup(exporterIP net.IP, ifIndex uint32) (enrich.InterfaceMetadata, bool) {
	if exporterIP == nil {
		return enrich.InterfaceMetadata{}, false
	}
	ifaces, ok := f.metadata[exporterIP.String()]
	if !ok {
		return enrich.InterfaceMetadata{}, false
	}
	meta, ok := ifaces[ifIndex]
	return meta, ok
}

func (f *fakeInterfaceEnricher) ObserveExporter(exporterIP net.IP) {}

func TestNtopngJSONEnrichment(t *testing.T) {
	SetInterfaceEnricher(&fakeInterfaceEnricher{
		metadata: map[string]map[uint32]enrich.InterfaceMetadata{
			"192.0.2.9": {
				10: {Name: "Port10", Alias: "Uplink", SpeedBps: 1_000_000_000},
				20: {Name: "Port20", Alias: "Downlink", SpeedBps: 100_000_000},
			},
		},
	})
	SetNDPIClassifier(enrich.NewNDPIClassifier(enrich.NDPIConfig{Enabled: true}))
	defer SetInterfaceEnricher(nil)
	defer SetNDPIClassifier(nil)

	baseFlow := &pb.FlowMessage{
		Etype:               0x800,
		SrcAddr:             net.IPv4(192, 0, 2, 1).To4(),
		DstAddr:             net.IPv4(192, 0, 2, 2).To4(),
		NextHop:             net.IPv4(192, 0, 2, 254).To4(),
		Proto:               17,
		SrcPort:             5060,
		DstPort:             5060,
		InIf:                10,
		OutIf:               20,
		SamplerAddress:      net.IPv4(192, 0, 2, 9).To4(),
		ObservationDomainId: 100,
		ObservationPointId:  7,
		TimeFlowStartNs:     1_000_000_000,
		TimeFlowEndNs:       2_000_000_000,
	}

	extFlow := &proto.ExtendedFlowMessage{
		BaseFlow:               baseFlow,
		ApplicationId:          5000,
		ApplicationName:        "SIP",
		ApplicationDescription: "Voice",
	}

	formatter := &NtopngJson{}
	data, err := formatter.toJSON(extFlow, nil)
	if err != nil {
		t.Fatalf("toJSON failed: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	if payload["in_ifName"] != "Port10" {
		t.Fatalf("expected in_ifName Port10")
	}
	if payload["out_ifAlias"] != "Downlink" {
		t.Fatalf("expected out_ifAlias Downlink")
	}
	if payload["ndpi.category"] != "sip" {
		t.Fatalf("expected ndpi.category sip")
	}

	obsDomainKey := strconv.Itoa(netflow.IPFIX_FIELD_observationDomainId)
	if payload[obsDomainKey] != float64(100) {
		t.Fatalf("expected observation domain id 100")
	}

	appNameKey := strconv.Itoa(netflow.IPFIX_FIELD_applicationName)
	if payload[appNameKey] != "SIP" {
		t.Fatalf("expected application name SIP")
	}
}
