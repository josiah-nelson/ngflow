package main

import (
	"net"

	"github.com/josiah-nelson/ngflow/collector"
	"github.com/josiah-nelson/ngflow/dedup"
	"github.com/josiah-nelson/ngflow/sampling"
	flowpb "github.com/netsampler/goflow2/v2/pb"
	"github.com/netsampler/goflow2/v2/producer"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
)

type flowMessageGetter interface {
	GetFlowMessage() *protoproducer.ProtoProducerMessage
}

type filteringProducer struct {
	inner     producer.ProducerInterface
	dedup     *dedup.DedupCache
	sampling  *sampling.SamplingTracker
	exporters *collector.ExporterRegistry
}

func newFilteringProducer(inner producer.ProducerInterface, dedupCache *dedup.DedupCache, tracker *sampling.SamplingTracker, exporters *collector.ExporterRegistry) producer.ProducerInterface {
	if dedupCache == nil && tracker == nil && exporters == nil {
		return inner
	}
	return &filteringProducer{
		inner:     inner,
		dedup:     dedupCache,
		sampling:  tracker,
		exporters: exporters,
	}
}

func (p *filteringProducer) Produce(msg interface{}, args *producer.ProduceArgs) ([]producer.ProducerMessage, error) {
	msgs, err := p.inner.Produce(msg, args)
	if err != nil || len(msgs) == 0 {
		return msgs, err
	}

	out := msgs[:0]
	for _, m := range msgs {
		flow := extractFlowMessage(m)
		if flow == nil {
			out = append(out, m)
			continue
		}

		p.updateSampling(flow)

		if p.dedup != nil && isDuplicateFlow(p.dedup, flow) {
			continue
		}

		p.recordExporterStats(flow)
		out = append(out, m)
	}

	return out, nil
}

func (p *filteringProducer) Commit(msgs []producer.ProducerMessage) {
	p.inner.Commit(msgs)
}

func (p *filteringProducer) Close() {
	p.inner.Close()
}

func extractFlowMessage(msg producer.ProducerMessage) *flowpb.FlowMessage {
	if getter, ok := msg.(flowMessageGetter); ok {
		if pm := getter.GetFlowMessage(); pm != nil {
			return &pm.FlowMessage
		}
	}
	if flow, ok := msg.(*flowpb.FlowMessage); ok {
		return flow
	}
	return nil
}

func (p *filteringProducer) updateSampling(flow *flowpb.FlowMessage) {
	if p.sampling == nil || flow == nil || flow.SamplingRate == 0 {
		return
	}
	if flow.Type == flowpb.FlowMessage_SFLOW_5 {
		return
	}

	source := sampling.SourceUnknown
	switch flow.Type {
	case flowpb.FlowMessage_NETFLOW_V9:
		source = sampling.SourceNetFlowV9
	case flowpb.FlowMessage_IPFIX:
		source = sampling.SourceIPFIXOptions
	}

	p.sampling.UpdateSamplingRate(
		net.IP(flow.SamplerAddress),
		flow.ObservationDomainId,
		uint32(flow.SamplingRate),
		sampling.SamplingDeterministic,
		source,
	)
}

func (p *filteringProducer) recordExporterStats(flow *flowpb.FlowMessage) {
	if p.exporters == nil || flow == nil {
		return
	}
	exporterIP := net.IP(flow.SamplerAddress)
	if exporterIP == nil {
		return
	}
	sourceID := flow.ObservationDomainId
	p.exporters.RecordPacket(exporterIP, sourceID, clampUint64ToInt(flow.Bytes))
	p.exporters.RecordFlows(exporterIP, sourceID, 1)
}
