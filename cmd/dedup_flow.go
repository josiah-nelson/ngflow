package main

import (
	"net"

	"github.com/josiah-nelson/ngflow/dedup"
	flowpb "github.com/netsampler/goflow2/v2/pb"
)

func isDuplicateFlow(cache *dedup.DedupCache, flow *flowpb.FlowMessage) bool {
	if cache == nil || flow == nil {
		return false
	}

	key := dedup.MakeFlowKey(
		net.IP(flow.SrcAddr),
		net.IP(flow.DstAddr),
		uint16(flow.SrcPort),
		uint16(flow.DstPort),
		uint8(flow.Proto),
		net.IP(flow.SamplerAddress),
		flow.ObservationDomainId,
	)

	return cache.CheckDuplicate(&key, flow.Bytes, flow.Packets, uint64(flow.SequenceNum))
}
