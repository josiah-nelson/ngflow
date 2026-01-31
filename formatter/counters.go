package formatter

import (
	"net"

	"github.com/josiah-nelson/ngflow/proto"
	"github.com/josiah-nelson/ngflow/sampling"
	flowpb "github.com/netsampler/goflow2/v2/pb"
)

var samplingTracker *sampling.SamplingTracker

func SetSamplingTracker(tracker *sampling.SamplingTracker) {
	samplingTracker = tracker
}

func resolveCounters(extFlow *proto.ExtendedFlowMessage) (inBytes, inPackets, outBytes, outPackets uint64) {
	if extFlow == nil || extFlow.BaseFlow == nil {
		return 0, 0, 0, 0
	}

	baseFlow := extFlow.BaseFlow
	inBytes = uint64(extFlow.InBytes)
	inPackets = uint64(extFlow.InPackets)
	outBytes = uint64(extFlow.OutBytes)
	outPackets = uint64(extFlow.OutPackets)

	if inBytes == 0 && outBytes == 0 && baseFlow.Bytes > 0 {
		inBytes = baseFlow.Bytes
		inPackets = baseFlow.Packets
	}

	if samplingTracker == nil || baseFlow.Type == flowpb.FlowMessage_SFLOW_5 {
		return inBytes, inPackets, outBytes, outPackets
	}

	exporterIP := net.IP(baseFlow.SamplerAddress)
	observationDom := baseFlow.ObservationDomainId

	if inBytes > 0 || inPackets > 0 {
		inBytes, inPackets = samplingTracker.ScaleFlow(exporterIP, observationDom, inBytes, inPackets)
	}
	if outBytes > 0 || outPackets > 0 {
		outBytes, outPackets = samplingTracker.ScaleFlow(exporterIP, observationDom, outBytes, outPackets)
	}

	return inBytes, inPackets, outBytes, outPackets
}
